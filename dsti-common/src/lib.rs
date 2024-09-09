#![no_std]

use core::default;

const TASK_NAME_LEN: u8 = 16;
const MAX_FILENAME_LEN: u16 = 512;

#[repr(C)]
#[derive(Debug)]
struct TraceEntry {
    entry_type: u16,
    flags: u8,
    preempt_count: u8,
    pid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NwEvent {
    pub src_addr: u32,
    pub dest_addr: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct Event {
    pub pid: u32,
    pub uid: u32,  
}

#[derive(Default)]
pub struct NwCount{
    pub count:u32,
}

// pub const TASK_COMM_LEN: usize = 16;
pub const ARGSIZE: usize = 128;
// pub const MAXARGS: usize = 20;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Config {
    pub use_allowlist: bool,
    pub use_denylist: bool,
    pub dry_run: bool,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SuidEvent {
    pub path: [u8; 4096],
    // pub uid: u32,
    // pub gid: u32,
    // pub denied: bool,
}

#[repr(C)]
#[derive(Debug)]
pub struct RenameEvent{
    pub uid: u32,
    pub pid: u32,
    pub o_filename: [u8; 4096],
    pub n_filename: [u8; 4096],
}
