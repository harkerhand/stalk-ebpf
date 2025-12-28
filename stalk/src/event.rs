#![allow(dead_code)]
use core::fmt::Display;

use serde::Serialize;
use stalk_common::{
    RawExecveEvent, RawExitEvent, RawOpenatEvent, RawReadEvent, RawReadEventExit, RawXdpEvent,
};
use tokio::time::Instant;

pub trait Event: Display {
    fn pid(&self) -> u32;
    fn start_time(&self) -> Instant;
    fn name(&self) -> String {
        format!("{:?}", core::any::type_name::<Self>())
    }
}

pub trait RawEvent {}

#[derive(Debug, Serialize)]
pub struct ExecveEvent {
    pub pid: u32,
    pub filename: String,
    pub argv: Vec<String>,
    #[serde(skip)]
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

#[derive(Debug, Serialize)]
pub struct ExitEvent {
    pub pid: u32,
    pub exit_code: u64,
    #[serde(skip)]
    pub start_time: Instant,
}

impl Display for ExitEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ExitEvent {{ pid: {}, exit_code: {} }}",
            self.pid, self.exit_code
        )
    }
}

impl Event for ExitEvent {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn start_time(&self) -> Instant {
        self.start_time
    }
}

impl From<RawExitEvent> for ExitEvent {
    fn from(value: RawExitEvent) -> Self {
        ExitEvent {
            pid: value.pid,
            exit_code: value.exit_code,
            start_time: Instant::now(),
        }
    }
}

impl RawEvent for RawExitEvent {}

#[derive(Debug, Serialize)]
pub struct ReadEvent {
    pub pid: u32,
    pub gid: u32,
    pub fd: u64,
    pub count: usize,
    #[serde(skip)]
    pub start_time: Instant,
    #[serde(skip)]
    pub end_time: Option<Instant>,
}

impl Display for ReadEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ReadEvent {{ pid: {}, fd: {}, count: {} }}",
            self.pid, self.fd, self.count
        )
    }
}

impl Event for ReadEvent {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn start_time(&self) -> Instant {
        self.start_time
    }
}

impl From<RawReadEvent> for ReadEvent {
    fn from(value: RawReadEvent) -> Self {
        ReadEvent {
            pid: value.pid,
            gid: value.gid,
            fd: value.fd,
            count: value.count,
            start_time: Instant::now(),
            end_time: None,
        }
    }
}

impl RawEvent for RawReadEvent {}

impl RawEvent for RawReadEventExit {}

#[derive(Debug, Serialize)]
pub struct OpenatEvent {
    pub pid: u32,
    pub filename: String,
    pub flags: u64,
    pub mode: u32,
    #[serde(skip)]
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

impl From<RawOpenatEvent> for OpenatEvent {
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

#[derive(Debug, Serialize)]
pub struct XdpEvent {
    pub pid: u32,
    pub source_addr: [u8; 4],
    pub dest_addr: [u8; 4],
    pub source_port: u16,
    pub dest_port: u16,
    #[serde(skip)]
    pub start_time: Instant,
}

impl Display for XdpEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "XdpEvent {{ source_addr: {}.{}.{}.{}, dest_addr: {}.{}.{}.{}, source_port: {}, dest_port: {} }}",
            self.source_addr[0],
            self.source_addr[1],
            self.source_addr[2],
            self.source_addr[3],
            self.dest_addr[0],
            self.dest_addr[1],
            self.dest_addr[2],
            self.dest_addr[3],
            self.source_port,
            self.dest_port
        )
    }
}

impl Event for XdpEvent {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn start_time(&self) -> Instant {
        self.start_time
    }
}

impl From<RawXdpEvent> for XdpEvent {
    fn from(value: RawXdpEvent) -> Self {
        let start_time = Instant::now();
        XdpEvent {
            pid: value.pid,
            source_addr: value.source_addr.to_be_bytes(),
            dest_addr: value.dest_addr.to_be_bytes(),
            source_port: value.source_port,
            dest_port: value.dest_port,
            start_time,
        }
    }
}

impl RawEvent for RawXdpEvent {}
