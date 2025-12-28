#![no_std]

#[repr(C)]
pub struct RawExecveEvent {
    pub pid: u32,
    pub filename: [u8; 64],
    pub argv: [[u8; 32]; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SysEnterExecveInfo {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub filename: *const core::ffi::c_char,
    pub argv: *const *const core::ffi::c_char,
    pub envp: *const *const core::ffi::c_char,
}

#[repr(C)]
#[derive(Debug)]
pub struct RawReadEvent {
    pub pid: u32,
    pub gid: u32,
    pub fd: u64,
    pub count: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SysEnterReadInfo {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub padding: u32,
    pub fd: u64,
    pub buf: *const core::ffi::c_char,
    pub count: usize,
}

#[repr(C)]
pub struct RawReadEventExit {
    pub pid: u32,
    pub gid: u32,
    pub ret: isize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SysExitReadInfo {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub padding: u32,
    pub ret: isize,
}

#[repr(C)]
pub struct RawOpenatEvent {
    pub pid: u32,
    pub gid: u32,
    pub filename: [u8; 64],
    pub flags: i64,
    pub mode: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SysEnterOpenatInfo {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub padding: u32,
    pub dfd: i64,
    pub filename: *const core::ffi::c_char,
    pub flags: i64,
    pub mode: u64,
}

#[repr(C)]
pub struct RawXdpEvent {
    pub pid: u32,
    pub source_addr: u32,
    pub dest_addr: u32,
    pub source_port: u16,
    pub dest_port: u16,
}

#[repr(C)]
pub struct RawExitEvent {
    pub pid: u32,
    pub error_code: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SysEnterExitGroupInfo {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub syscall_nr: i32,
    pub error_code: i32,
}
