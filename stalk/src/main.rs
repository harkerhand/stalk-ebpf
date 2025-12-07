use aya::{maps::PerfEventArray, programs::TracePoint};
use bytes::BytesMut;
#[rustfmt::skip]
use log::{debug, warn};
use std::{collections::HashMap, process::exit, sync::Arc};

use event::{ExecveEvent, ReadEvent};
use stalk_common::{RawExecveEvent, RawReadEvent, RawReadEventExit};
use tokio::{io::unix::AsyncFd, signal, sync::Mutex};

mod event;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    init_rlimit()?;
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/stalk"
    )))?;
    init_ebpf(&mut ebpf)?;
    let program: &mut TracePoint = ebpf.program_mut("stalk_execve").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;
    tokio::task::spawn(async move {
        let mut perf_array =
            PerfEventArray::try_from(ebpf.map_mut("EXECVE_EVENTS").unwrap()).unwrap();
        let array_buf = perf_array.open(0, None).unwrap();
        let mut async_array_buf =
            match AsyncFd::with_interest(array_buf, tokio::io::Interest::READABLE) {
                Ok(buf) => buf,
                Err(e) => {
                    // 处理错误
                    eprintln!("Failed to create AsyncFd for PerfEventArray: {e}");
                    return;
                }
            };
        let mut buffer = vec![BytesMut::with_capacity(size_of::<RawExecveEvent>())];
        loop {
            let mut guard = match async_array_buf.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    eprintln!("Error waiting for readable: {e}");
                    break;
                }
            };
            match guard.get_inner_mut().read_events(&mut buffer) {
                Ok(events) => {
                    guard.clear_ready();
                    for i in 0..events.read {
                        let buf = &buffer[i];
                        let ptr = buf.as_ptr() as *const RawExecveEvent;
                        let raw_event = unsafe { ptr.read_unaligned() };
                        let event: ExecveEvent = raw_event.into();
                        println!("{}", event);
                    }
                }
                Err(e) => {
                    eprintln!("Error reading events: {e}");
                    break;
                }
            }
        }
    });

    let read_event_map = Arc::new(Mutex::new(HashMap::new()));
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/stalk"
    )))?;
    init_ebpf(&mut ebpf)?;
    let program: &mut TracePoint = ebpf.program_mut("stalk_read").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_read")?;
    let map_clone = read_event_map.clone();
    tokio::task::spawn(async move {
        let mut perf_array =
            PerfEventArray::try_from(ebpf.map_mut("READ_EVENTS").unwrap()).unwrap();
        let array_buf = perf_array.open(0, None).unwrap();
        let mut async_array_buf =
            match AsyncFd::with_interest(array_buf, tokio::io::Interest::READABLE) {
                Ok(buf) => buf,
                Err(e) => {
                    // 处理错误
                    eprintln!("Failed to create AsyncFd for PerfEventArray: {e}");
                    return;
                }
            };
        let mut buffer = vec![BytesMut::with_capacity(size_of::<RawReadEvent>())];
        loop {
            let mut guard = match async_array_buf.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    eprintln!("Error waiting for readable: {e}");
                    break;
                }
            };
            match guard.get_inner_mut().read_events(&mut buffer) {
                Ok(events) => {
                    guard.clear_ready();
                    for i in 0..events.read {
                        let buf = &buffer[i];
                        let ptr = buf.as_ptr() as *const RawReadEvent;
                        let raw_event = unsafe { ptr.read_unaligned() };
                        let tpid_gid = ((raw_event.gid as u64) << 32) | (raw_event.pid as u64);
                        let event: ReadEvent = raw_event.into();
                        let mut map = map_clone.lock().await;
                        map.insert(tpid_gid, event);
                    }
                }
                Err(e) => {
                    eprintln!("Error reading events: {e}");
                    break;
                }
            }
        }
    });

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/stalk"
    )))?;
    init_ebpf(&mut ebpf)?;
    let program: &mut TracePoint = ebpf.program_mut("stalk_read_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_read")?;
    let map_clone = read_event_map.clone();
    tokio::task::spawn(async move {
        let mut perf_array =
            PerfEventArray::try_from(ebpf.map_mut("READ_EXIT_EVENTS").unwrap()).unwrap();
        let array_buf = perf_array.open(0, None).unwrap();
        let mut async_array_buf =
            match AsyncFd::with_interest(array_buf, tokio::io::Interest::READABLE) {
                Ok(buf) => buf,
                Err(e) => {
                    // 处理错误
                    eprintln!("Failed to create AsyncFd for PerfEventArray: {e}");
                    return;
                }
            };
        let mut buffer = vec![BytesMut::with_capacity(size_of::<RawReadEvent>())];
        loop {
            let mut guard = match async_array_buf.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    eprintln!("Error waiting for readable: {e}");
                    break;
                }
            };
            match guard.get_inner_mut().read_events(&mut buffer) {
                Ok(events) => {
                    guard.clear_ready();
                    for i in 0..events.read {
                        let buf = &buffer[i];
                        let ptr = buf.as_ptr() as *const RawReadEventExit;
                        let raw_event = unsafe { ptr.read_unaligned() };
                        let tpid_gid = ((raw_event.gid as u64) << 32) | (raw_event.pid as u64);
                        let mut map = map_clone.lock().await;
                        if let Some(read_event) = map.remove(&tpid_gid) {
                            let duration = read_event.time.elapsed();
                            println!("{}, duration: {:?}", read_event, duration);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading events: {e}");
                    break;
                }
            }
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    exit(0);
}

fn init_rlimit() -> anyhow::Result<()> {
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
    Ok(())
}

fn init_ebpf(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    match aya_log::EbpfLogger::init(ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    Ok(())
}
