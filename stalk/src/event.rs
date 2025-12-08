#![allow(dead_code)]
use core::fmt::Display;

use stalk_common::{RawExecveEvent, RawReadEvent, RawReadEventExit};
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
    filename: String,
    pub start_time: Instant,
    pub end_time: Option<Instant>,
}
impl Display for ReadEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ReadEvent {{ pid: {}, filename: {}, count: {} }}",
            self.raw.pid, self.filename, self.raw.count
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
        let pid = value.pid;
        let fd = value.fd;
        let file_path = format!("/proc/{}/fd/{}", pid, fd);
        let filename = std::fs::read_link(file_path)
            .map(|path_buf| path_buf.to_string_lossy().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        ReadEvent {
            raw: value,
            filename,
            start_time: Instant::now(),
            end_time: None,
        }
    }
}

impl RawEvent for RawReadEvent {}

impl RawEvent for RawReadEventExit {}
