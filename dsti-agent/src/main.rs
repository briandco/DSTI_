use std::{
    collections::HashMap, fs, path::PathBuf, result::Result::Ok, 
};
// use anyhow::Ok;
use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, RingBuf},
    programs::{Lsm, TracePoint},
    util::online_cpus,
    Btf, Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use dsti_common::SuidEvent;
use log::{info, warn};
use rlimit::Resource;
use tokio::{signal, task};
use once_cell::sync::Lazy; 

mod syscall;
mod network;
mod process;

// A smaller Event struct used in Arc<DashMap<T>> in userspace program
#[derive(Debug)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub filename: String,
}

// Static mutable vectors and lazy-initialized HashMap
pub static mut SUDO_PID: Vec<u32> = Vec::new();
pub static mut PROCESS_BY_SUDO: Vec<u32> = Vec::new();
static mut FORKED_BY_SUDO_PROCESS: Lazy<HashMap<u32, Vec<u32>>> = Lazy::new(|| HashMap::new());

fn bytes_to_str(bytes: &[u8]) -> Result<&str, anyhow::Error> {
    if let Some(first_null_position) = bytes.iter().position(|&x| x == 0) {
        let Ok(bytes) = std::str::from_utf8(&bytes[..first_null_position]) else {
            return Err(anyhow::anyhow!("invalid utf8"));
        };
        Ok(bytes)
    } else {
        Err(anyhow::anyhow!("no null terminator"))
    }
}

async fn insert_ebpf_fs() -> Result<(), anyhow::Error> {
    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    // #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/file-sys"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("file_open").unwrap().try_into()?;
    program.load("file_open", &btf)?;
    program.attach()?;

    // Process events from the perf buffer
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(bpf.take_map("NET_EVENTS").unwrap())?;

    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    // read the event
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const SuidEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    let pathname =
                        String::from_utf8(data.path.to_vec()).unwrap_or("Unknown".to_owned());

                    info!("file_open: path: {}", pathname);
                }
            }
        })
        .await
        .unwrap();
    }
    Ok(())
}

// Read process status from /proc/<pid>/status
fn read_process_status(pid: u32) -> Option<(String, i32, i32)> {
    let status_path = PathBuf::from(format!("/proc/{}/status", pid));
    let status_content = fs::read_to_string(status_path).ok()?;

    let mut process_name = String::new();
    let mut uid = 0;
    let mut ppid = 0;

    for line in status_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "Name:" => {
                    process_name = parts[1].to_string();
                }
                "PPid:" => {
                    ppid = parts[1].parse().unwrap_or(0);
                }
                "Uid:" => {
                    uid = parts[1].parse().unwrap_or(0);
                    break;
                }
                _ => {}
            }
        }
    }
    if !process_name.is_empty() {
        Some((process_name, ppid, uid))
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    if !Resource::MEMLOCK
        .set(rlimit::INFINITY, rlimit::INFINITY)
        .is_ok()
    {
        warn!("cannot remove mem lock");
    }

    // let fs_handle = tokio::spawn(insert_ebpf_fs());

    let process_handle = tokio::spawn(process::insert_and_monitor_process());
    
    let nw_handle: task::JoinHandle<Result<Ebpf, anyhow::Error>> = tokio::spawn(network::insert_ebpf_nw());
    
    let syscall_getrandom = tokio::spawn(syscall::monitor_syscall_get_random());

    let syscall_open = tokio::spawn(syscall::monitor_syscall_open());

    let _ = tokio::try_join!( process_handle, nw_handle, syscall_getrandom, syscall_open)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
