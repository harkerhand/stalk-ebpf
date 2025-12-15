use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use stalk_common::{RawOpenatEvent, SysEnterOpenatInfo};

#[map]
static mut OPENAT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn stalk_openat(ctx: TracePointContext) -> u32 {
    try_stalk_openat(ctx).unwrap_or_else(|ret| ret)
}

fn try_stalk_openat(ctx: TracePointContext) -> Result<u32, u32> {
    let tgid_pid = bpf_get_current_pid_tgid();
    let pid = (tgid_pid & 0xFFFFFFFF) as u32;
    let gid = (tgid_pid >> 32) as u32;
    unsafe {
        let openat_info: *const SysEnterOpenatInfo = ctx.as_ptr() as *const SysEnterOpenatInfo;
        let filename_ptr = (*openat_info).filename;
        let mut filename: [u8; 64] = [0; 64];
        let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut filename);
        let flags = (*openat_info).flags;
        let mode = (*openat_info).mode;
        let event = RawOpenatEvent {
            pid,
            gid,
            filename,
            flags,
            mode,
        };
        let event_map = &raw mut OPENAT_EVENTS;
        if let Some(mut buf) = (*event_map).reserve::<RawOpenatEvent>(0) {
            buf.write(event);
            buf.submit(0);
        }
    }
    Ok(0)
}
