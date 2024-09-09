use aya::{include_bytes_aligned, maps::RingBuf, programs::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn};
use crate::read_process_status;

pub async fn monitor_syscall_get_random()-> Result<(), anyhow::Error>{
    // Load the eBPF program
    // #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/syscall-tp"
    ))?;

    // Initialize the eBPF logger
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let syscall_name = "sys_enter_getrandom";
    // Load and attach the program
    let program: &mut TracePoint = bpf.program_mut("syscall_tp").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", &syscall_name)?;

    let mut ring = RingBuf::try_from(bpf.map_mut("SYSCALL_DATA").unwrap())?;
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
                        info!("syscall {} is been called by {}, with parent 
                        pid {}", syscall_name, process_name, value.2);
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

pub async fn monitor_syscall_open()-> Result<(), anyhow::Error>{
    // Load the eBPF program
    // #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/syscall-tp"
    ))?;

    // Initialize the eBPF logger
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let syscall_name = "sys_enter_open";
    // Load and attach the program
    let program: &mut TracePoint = bpf.program_mut("syscall_open").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", &syscall_name)?;

    let mut ring = RingBuf::try_from(bpf.map_mut("SYSCALL_DATA").unwrap())?;
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
                        info!("syscall {} is been called by {}, with parent 
                        pid {}", syscall_name, process_name, value.2);
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

