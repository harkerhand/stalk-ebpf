#![no_std]
#![no_main]

mod tracepoint;
mod xdp;

use aya_ebpf::{macros::map, maps::RingBuf};
use stalk_common::{RawExecveEvent, RawOpenatEvent, RawReadEvent, RawReadEventExit, RawXdpEvent, RawExitEvent};

#[map]
static EXECVE_EVENTS: RingBuf<RawExecveEvent> = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static OPENAT_EVENTS: RingBuf<RawOpenatEvent> = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static READ_EVENTS: RingBuf<RawReadEvent> = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static READ_EXIT_EVENTS: RingBuf<RawReadEventExit> = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static XDP_EVENTS: RingBuf<RawXdpEvent> = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static TRACEPOINT_EXIT_EVENTS: RingBuf<RawExitEvent> = RingBuf::with_byte_size(1024 * 1024, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
