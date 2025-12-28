use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use stalk_common::{RawExitEvent, SysEnterExitGroupInfo};

use crate::TRACEPOINT_EXIT_EVENTS;

#[tracepoint]
pub fn stalk_exit_group(ctx: TracePointContext) -> u32 {
    match try_stalk_exit_group(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_stalk_exit_group(ctx: TracePointContext) -> Result<u32, i64> {
    const EXIT_GROUP_Info_SIZE: usize = core::mem::size_of::<SysEnterExitGroupInfo>();
    let info = unsafe { ctx.read_at::<SysEnterExitGroupInfo>(0)? };
    
    let pid = ctx.pid();
    
    let event = RawExitEvent {
        pid,
        error_code: info.error_code,
    };

    unsafe {
        TRACEPOINT_EXIT_EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}
