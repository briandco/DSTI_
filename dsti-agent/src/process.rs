use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn};
use crate::read_process_status;

pub async fn insert_and_monitor_process()-> Result<(), anyhow::Error>{
    // Load the eBPF program
    // #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/proc"
    ))?;

    // Initialize the eBPF logger
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Load and attach the program
    let program: &mut TracePoint = bpf.program_mut("proc").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let mut ring = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;
    let _ = ring.next();
    loop {
        if let Some(item) = ring.next() {
            // Interpret bytes as u32 values representing IPv4 addresses
            let pid_bytes: [u8; 4] = item[..4].try_into().unwrap();
            let uid_bytes: [u8; 4] = item[4..].try_into().unwrap();

            // Convert u8 arrays to u32 values
            let pid = u32::from_le_bytes(pid_bytes);
            let uid = u32::from_le_bytes(uid_bytes);
            match read_process_status(pid){
                Some(value) => {
                    let process_name = value.0;
                    if uid == 0{
                        info!("Sudo process {} spawned with pid {}", process_name, pid);
                    }
                }
                None => {
                    if uid ==0 {
                        info!("process info not available for pid {}", pid);
                    }
                }
            }
        }
    }
} 
