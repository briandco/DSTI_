use aya::{include_bytes_aligned, maps::RingBuf, programs::KProbe, Ebpf};
use aya_log::EbpfLogger;
use dsti_common::NwCount;
use log::{info, warn};
use std::{collections::HashMap, net::Ipv4Addr};

pub async fn insert_ebpf_nw() -> Result<Ebpf, anyhow::Error> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    // #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/dsti-net-bpf"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("kprobetcp").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;

    let mut ring = RingBuf::try_from(bpf.map_mut("DATA").unwrap())?;
    let _ = ring.next();
    let mut packet_count_map = HashMap::<Ipv4Addr, NwCount>::default();
    loop {
        if let Some(item) = ring.next() {
            // Interpret bytes as u32 values representing IPv4 addresses
            let src_addr_bytes: [u8; 4] = item[..4].try_into().unwrap();
            let dest_addr_bytes: [u8; 4] = item[4..].try_into().unwrap();

            // Convert u8 arrays to u32 values
            let src_addr_u32 = u32::from_le_bytes(src_addr_bytes);
            let dest_addr_u32 = u32::from_le_bytes(dest_addr_bytes);

            // Convert u32 values to Ipv4Addr
            let src_addr = Ipv4Addr::from(src_addr_u32);
            let dest_addr = Ipv4Addr::from(dest_addr_u32);

            info!("Src address: {}, Dest address: {}", src_addr, dest_addr);

            match packet_count_map.get_mut(&dest_addr)
            {
                Some(count)=> {count.count+=1;}
                None => {
                    packet_count_map.insert(dest_addr, NwCount { count: 1 }); 
                }
            };

            // Print the updated count
            if let Some(count) = packet_count_map.get(&dest_addr) {
                println!("Count for {:?}: {}", dest_addr, count.count);
            }
        }   
    }
}