#![allow(dead_code)]
use core::fmt::Display;

use stalk_common::{RawExecveEvent, RawOpenatEvent, RawReadEvent, RawReadEventExit};
use tokio::time::Instant;

pub trait Event: Display {
    fn pid(&self) -> u32;
    fn start_time(&self) -> Instant;
    fn name(&self) -> String {
        format!("{:?}", core::any::type_name::<Self>())
    }
}

pub trait RawEvent {}

#[derive(Debug)]
pub struct ExecveEvent {
    pub pid: u32,
    pub filename: String,
    pub argv: Vec<String>,
    pub start_time: Instant,
}

impl Display for ExecveEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ExecveEvent {{ pid: {}, filename: {}, argv: {:?} }}",
            self.pid, self.filename, self.argv
        )
    }
}

impl Event for ExecveEvent {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn start_time(&self) -> Instant {
        self.start_time
    }
}

impl From<RawExecveEvent> for ExecveEvent {
    fn from(value: RawExecveEvent) -> Self {
        let start_time = Instant::now();
        let filename_cstr = unsafe {
            let len = value
                .filename
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(value.filename.len());
            std::ffi::CStr::from_bytes_with_nul_unchecked(&value.filename[..=len])
        };
        let filename_str = filename_cstr.to_string_lossy().to_string();
        let mut argv_vec = Vec::new();
        for arg in &value.argv {
            let len = arg.iter().position(|&c| c == 0).unwrap_or(arg.len());
            if len > 0 {
                let arg_cstr =
                    unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(&arg[..=len]) };
                let arg_str = arg_cstr.to_string_lossy().to_string();
                argv_vec.push(arg_str);
            }
        }
        ExecveEvent {
            pid: value.pid,
            filename: filename_str,
            argv: argv_vec,
            start_time,
        }
    }
}

impl RawEvent for RawExecveEvent {}
pub struct ReadEvent {
    raw: RawReadEvent,
    pub start_time: Instant,
    pub end_time: Option<Instant>,
}
impl Display for ReadEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ReadEvent {{ pid: {}, fd: {}, count: {} }}",
            self.raw.pid, self.raw.fd, self.raw.count
        )
    }
}

impl Event for ReadEvent {
    fn pid(&self) -> u32 {
        self.raw.pid
    }
    fn start_time(&self) -> Instant {
        self.start_time
    }
}

impl From<RawReadEvent> for ReadEvent {
    fn from(value: RawReadEvent) -> Self {
        ReadEvent {
            raw: value,
            start_time: Instant::now(),
            end_time: None,
        }
    }
}

impl RawEvent for RawReadEvent {}

impl RawEvent for RawReadEventExit {}

pub struct OpenatEvent {
    pub pid: u32,
    pub filename: String,
    pub flags: u64,
    pub mode: u32,
    pub start_time: Instant,
}

impl Display for OpenatEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "OpenatEvent {{ pid: {}, filename: {}, flags: {}, mode: {} }}",
            self.pid, self.filename, self.flags, self.mode
        )
    }
}

impl Event for OpenatEvent {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn start_time(&self) -> Instant {
        self.start_time
    }
}

impl From<stalk_common::RawOpenatEvent> for OpenatEvent {
    fn from(value: RawOpenatEvent) -> Self {
        let start_time = Instant::now();
        let filename_cstr = unsafe {
            let len = value
                .filename
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(value.filename.len());
            std::ffi::CStr::from_bytes_with_nul_unchecked(&value.filename[..=len])
        };
        let filename_str = filename_cstr.to_string_lossy().to_string();
        OpenatEvent {
            pid: value.pid,
            filename: filename_str,
            flags: value.flags as u64,
            mode: value.mode as u32,
            start_time,
        }
    }
}

impl RawEvent for RawOpenatEvent {}
