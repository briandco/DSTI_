#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]
#![allow(warnings)]
mod binding;

use crate::binding::{sock, sock_common};

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{kprobe, map, raw_tracepoint},
    maps::{ HashMap, PerfEventArray, RingBuf},
    programs::{ProbeContext, RawTracePointContext},
};
use aya_log_ebpf::info;
use dsti_common::NwEvent;
use dsti_common::NwCount;


// #[map(name = "NET_EVENTS")]
// static NET_EVENTS: PerfEventArray<NwEvent> = PerfEventArray::<NwEvent>::with_max_entries(1024, 0);

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

// #[map]
// pub static packet_count_map: HashMap<u32, NwCount> = HashMap::pinned(1024, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[kprobe]
pub fn kprobetcp(ctx: ProbeContext) -> u32 {
    match try_kprobetcp(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_kprobetcp(ctx: ProbeContext) -> Result<u32, i64> {
    let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common).map_err(|e| e)?
    };
    match sk_common.skc_family {
        AF_INET => {
            let src_addr =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let dest_addr: u32 =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });

                
                // let mut count = NwCount{count:1};
                // packet_count_map.insert(&dest_addr, &count,0);

                // let mut count = packet_count_map.get_ptr_mut(&dest_addr)
                // .unwrap_or_else(|| packet_count_map.insert(&dest_addr, &count,0));
                
            // if let Some(mut count) = Nw_Count.reserve::<NwCount>(0){

            // }

            // let log_entry = NwEvent {
            //     src_addr,
            //     dest_addr,
            // };
            // NET_EVENTS.output(&ctx, &log_entry, 0);
            if let Some(mut buf) = DATA.reserve::<NwEvent>(0) {
                // let len = ctx.skb.len() as usize;

                unsafe { (*buf.as_mut_ptr()).src_addr = src_addr };
                unsafe { (*buf.as_mut_ptr()).dest_addr = dest_addr };

                buf.submit(0);
            }

            // info!(
            //     &ctx,
            //     "AF_INET src address: {:i}, dest address: {:i}", src_addr, dest_addr,
            // );
            Ok(0)
        }
        AF_INET6 => {
            let src_addr = sk_common.skc_v6_rcv_saddr;
            let dest_addr = sk_common.skc_v6_daddr;
            info!(
                &ctx,
                "AF_INET6 src addr: {:i}, dest addr: {:i}",
                unsafe { src_addr.in6_u.u6_addr8 },
                unsafe { dest_addr.in6_u.u6_addr8 }
            );
            Ok(0)
        }
        _ => Ok(0),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
