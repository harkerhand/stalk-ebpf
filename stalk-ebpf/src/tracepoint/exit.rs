use aya_ebpf::{
    EbpfContext,
    helpers::bpf_get_current_pid_tgid,
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use stalk_common::{RawExitEvent, SysEnterExitGroupInfo};

#[map]
static mut EXIT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn stalk_exit_group(ctx: TracePointContext) -> u32 {
    match try_stalk_exit_group(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_stalk_exit_group(ctx: TracePointContext) -> Result<u32, i64> {
    let tgid_pid = bpf_get_current_pid_tgid();
    let pid = (tgid_pid & 0xFFFFFFFF) as u32;
    unsafe {
        let exit_info: *const SysEnterExitGroupInfo = ctx.as_ptr() as *const SysEnterExitGroupInfo;
        let exit_code = (*exit_info).error_code;
        let event = RawExitEvent { pid, exit_code };
        let event_map = &raw mut EXIT_EVENTS;
        if let Some(mut buf) = (*event_map).reserve::<RawExitEvent>(0) {
            buf.write(event);
            buf.submit(0);
        }
    }
    Ok(0)
}
