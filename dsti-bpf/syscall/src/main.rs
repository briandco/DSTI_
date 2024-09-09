#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_long, helpers::bpf_probe_read_user_str_bytes, macros::{map, tracepoint}, 
    maps::{PerCpuArray, RingBuf}, programs::TracePointContext, EbpfContext
};
use aya_log_ebpf::info;
use dsti_common::{RenameEvent, Event};
use core::ops::DerefMut;

#[tracepoint]
pub fn syscall_tp(ctx: TracePointContext) -> c_long {
    match try_syscall_tp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn syscall_open(ctx: TracePointContext) -> c_long {
    match try_syscall_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[repr(C)]
struct FileName{
    name: [u8; 4096],
}

#[map]
static SYSCALL_DATA: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

#[map]
static SYSCALL_OPEN: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

#[map]
pub static mut BUF: PerCpuArray<RenameEvent> = PerCpuArray::with_max_entries(1, 0);

fn try_syscall_tp(ctx: TracePointContext) -> Result<c_long, c_long> {
    let uid = ctx.uid();
    // let mut _char_buf: [u8; 100];
    // Load the pointer to the filename. The offset value can be found running:
    // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_rename/format
    // let file_name_addr: u64 = unsafe { ctx.read_at(16)? };

    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };
    
    // let o_file_name = unsafe {
    //     core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
    //         file_name_addr as *const u8, 
    //         &mut buf.o_filename,
    //     )?)
    // };
    // let _n_file_name = unsafe {
    //     core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
    //         file_name_addr as *const u8, 
    //         &mut buf.n_filename,
    //     )?)
    // };
    buf.uid = uid;
    buf.pid = ctx.pid();
    let buf_entry = SYSCALL_DATA.reserve::<Event>(0);
    match buf_entry{
        Some(mut val) => {
            let e = unsafe { val.deref_mut().assume_init_mut() };
            e.pid = ctx.pid();
            e.uid = ctx.uid();
            
            val.submit(0);
        }
        None => return Err(1),
    }
    // let _ = &info!(&ctx, " file {} is renamed by sudo user in process {} ",o_file_name, ctx.pid());
    
    Ok(0)
}


fn try_syscall_open(ctx: TracePointContext) -> Result<c_long, c_long>{
    // buf.uid = uid;
    // buf.pid = ctx.pid();
    let buf_entry = SYSCALL_OPEN.reserve::<Event>(0);
    match buf_entry{
        Some(mut val) => {
            let e = unsafe { val.deref_mut().assume_init_mut() };
            e.pid = ctx.pid();
            e.uid = ctx.uid();
            
            val.submit(0);
        }
        None => return Err(1),
    }
    // let _ = &info!(&ctx, " file {} is renamed by sudo user in process {} ",o_file_name, ctx.pid());
    
    Ok(0)
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
