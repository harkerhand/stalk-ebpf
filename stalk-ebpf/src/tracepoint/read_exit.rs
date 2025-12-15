use aya_ebpf::{
    EbpfContext,
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use stalk_common::{RawReadEventExit, SysExitReadInfo};

#[map]
static mut READ_EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn stalk_read_exit(ctx: TracePointContext) -> u32 {
    try_stalk_read_exit(ctx).unwrap_or_else(|ret| ret)
}

fn try_stalk_read_exit(ctx: TracePointContext) -> Result<u32, u32> {
    let tgid_pid = bpf_get_current_pid_tgid();
    let pid = (tgid_pid & 0xFFFFFFFF) as u32;
    let gid = (tgid_pid >> 32) as u32;
    unsafe {
        let read_info: *const SysExitReadInfo = ctx.as_ptr() as *const SysExitReadInfo;
        let ret = (*read_info).ret;
        let event = RawReadEventExit { pid, gid, ret };
        let event_map = &raw mut READ_EXIT_EVENTS;
        if let Some(mut buf) = (*event_map).reserve::<RawReadEventExit>(0) {
            buf.write(event);
            buf.submit(0);
        }
    }
    Ok(0)
}
