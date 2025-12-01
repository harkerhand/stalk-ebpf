#![no_std]

#[repr(C)]
pub struct ProcessEvent {
    pub pid: u32,
    pub filename: [u8; 32],
    pub argv: [[u8; 16]; 4],
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