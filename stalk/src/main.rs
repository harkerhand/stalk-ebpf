use aya::maps::PerfEventArray;
use aya::programs::TracePoint;
use bytes::BytesMut;
#[rustfmt::skip]
use log::{debug, warn};
use stalk_common::ProcessEvent;
use std::process::exit;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/stalk"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut TracePoint = ebpf.program_mut("stalk").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    tokio::task::spawn(async move {
        let mut perf_array = PerfEventArray::try_from(ebpf.map_mut("EVENTS").unwrap()).unwrap();
        let mut buffer = vec![BytesMut::with_capacity(size_of::<ProcessEvent>())];
        let mut array_buf = perf_array.open(0, None).unwrap();
        loop {
            let events = array_buf.read_events(&mut buffer).unwrap();
            for i in 0..events.read {
                let buf = &buffer[i];
                let ptr = buf.as_ptr() as *const ProcessEvent;
                let event = unsafe { ptr.read_unaligned() };
                let filename_cstr = unsafe {
                    let len = event
                        .filename
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(event.filename.len());
                    std::ffi::CStr::from_bytes_with_nul_unchecked(&event.filename[..=len])
                };
                let filename_str = filename_cstr.to_string_lossy();
                // if !filename_str.contains("ls") {
                //     continue;
                // }
                let mut argv_vec = Vec::new();
                for arg in &event.argv {
                    let len = arg.iter().position(|&c| c == 0).unwrap_or(arg.len());
                    if len > 0 {
                        let arg_cstr = unsafe {
                            std::ffi::CStr::from_bytes_with_nul_unchecked(&arg[..=len])
                        };
                        let arg_str = arg_cstr.to_string_lossy();
                        argv_vec.push(arg_str.to_string());
                    }
                }
                println!("Process execve detected: PID={}", event.pid);
                println!("Filename: {}", filename_str);
                println!("Arguments: {:?}", argv_vec);
            }
        }
    });
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    exit(0);
}
