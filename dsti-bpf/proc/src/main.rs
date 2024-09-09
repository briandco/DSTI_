#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint}, maps::{RingBuf}, programs::TracePointContext, EbpfContext, PtRegs
};
use aya_log_ebpf::info;
use dsti_common::Event;

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

#[tracepoint]
pub fn proc(ctx: TracePointContext) -> u32 {
    match try_proc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_proc(ctx: TracePointContext) -> Result<u32, u32> {

    if let Some(mut buf) = unsafe { EVENTS.reserve::<Event>(0) } {
        // let len = ctx.skb.len() as usize;

        unsafe { (*buf.as_mut_ptr()).pid = ctx.pid() };
        unsafe { (*buf.as_mut_ptr()).uid = ctx.uid() };

        buf.submit(0);
    }
    
    // info!(&ctx, "tracepoint sched_process_exec called for {} and uid is {}",ctx.pid(), ctx.uid());
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
