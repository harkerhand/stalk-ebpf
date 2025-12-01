#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::error;
use stalk_common::{ProcessEvent, SysEnterExecveInfo};

#[map]
static mut EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn stalk(ctx: TracePointContext) -> u32 {
    try_stalk(ctx).unwrap_or_else(|ret| ret)
}

fn try_stalk(ctx: TracePointContext) -> Result<u32, u32> {
    let tgid_pid = bpf_get_current_pid_tgid();
    let pid = (tgid_pid & 0xFFFFFFFF) as u32;
    let mut filename = [0u8; 32];
    let mut argv: [[u8; 16]; 4] = [[0u8; 16]; 4];
    unsafe {
        let execve_info: *const SysEnterExecveInfo = ctx.as_ptr() as *const SysEnterExecveInfo;
        let filename_ptr = (*execve_info).filename;
        let res = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
            filename_ptr as *const u8,
            &mut filename,
        );
        if res.is_err() {
            error!(&ctx, "Failed to read filename");
            return Err(res.unwrap_err() as u32);
        }
        let argv_ptr = (*execve_info).argv;
        for i in 0..4 {
            let ptr_to_arg_ptr_usr: *const *const core::ffi::c_char = argv_ptr.add(i);
            let arg_ptr = aya_ebpf::helpers::bpf_probe_read_user(ptr_to_arg_ptr_usr)
                .map_err(|e| e as u32)? as *const u8;
            if arg_ptr.is_null() {
                break;
            }
            let res = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(arg_ptr, &mut argv[i]);
            if res.is_err() {
                error!(&ctx, "Failed to read argv[{}]", i);
                return Err(res.unwrap_err() as u32);
            }
        }
    }
    let event = ProcessEvent {
        pid,
        filename,
        argv,
    };

    unsafe {
        let event_map = &raw mut EVENTS;
        (*event_map).output(&ctx, &event, 0);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
