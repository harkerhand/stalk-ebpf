use core::fmt::Display;

use stalk_common::RawExecveEvent;

#[derive(Debug)]
pub struct ExecveEvent {
    pub pid: u32,
    pub filename: String,
    pub argv: Vec<String>,
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

impl From<RawExecveEvent> for ExecveEvent {
    fn from(value: RawExecveEvent) -> Self {
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
        }
    }
}
