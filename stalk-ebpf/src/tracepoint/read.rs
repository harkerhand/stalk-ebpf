use aya_ebpf::{
    EbpfContext,
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use stalk_common::{RawReadEvent, SysEnterReadInfo};

#[map]
static mut READ_EVENTS: PerfEventArray<RawReadEvent> = PerfEventArray::new(0);

#[tracepoint]
pub fn stalk_read(ctx: TracePointContext) -> u32 {
    try_stalk_read(ctx).unwrap_or_else(|ret| ret)
}

fn try_stalk_read(ctx: TracePointContext) -> Result<u32, u32> {
    let tgid_pid = bpf_get_current_pid_tgid();
    let pid = (tgid_pid & 0xFFFFFFFF) as u32;
    let gid = (tgid_pid >> 32) as u32;
    unsafe {
        let read_info: *const SysEnterReadInfo = ctx.as_ptr() as *const SysEnterReadInfo;
        let fd = (*read_info).fd;
        let count = (*read_info).count;
        let event = RawReadEvent {
            pid,
            gid,
            fd,
            count,
        };
        let event_map = &raw mut READ_EVENTS;
        (*event_map).output(&ctx, &event, 0);
    }
    Ok(0)
}
