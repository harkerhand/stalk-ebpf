use aya::{maps::PerfEventArray, programs::TracePoint};
use bytes::BytesMut;
#[rustfmt::skip]
use log::{debug, warn};
use std::{collections::HashMap, process::exit, sync::Arc};

use event::{ExecveEvent, OpenatEvent, ReadEvent};
use stalk_common::{RawExecveEvent, RawOpenatEvent, RawReadEvent, RawReadEventExit};
use tokio::{io::unix::AsyncFd, signal, sync::Mutex};

mod event;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    init_rlimit()?;
    tokio::task::spawn(async move {
        let _ = handle_tracepoint(
            "stalk_execve",
            ["syscalls", "sys_enter_execve"],
            "EXECVE_EVENTS",
            async move |raw_event: RawExecveEvent| {
                let event: ExecveEvent = raw_event.into();
                println!("{}", event);
                Ok(())
            },
        )
        .await;
    });

    let read_event_map = Arc::new(Mutex::new(HashMap::new()));
    let map_clone = read_event_map.clone();
    tokio::task::spawn(async move {
        let _ = handle_tracepoint(
            "stalk_read",
            ["syscalls", "sys_enter_read"],
            "READ_EVENTS",
            async move |raw_event: RawReadEvent| {
                let tpid_gid = ((raw_event.gid as u64) << 32) | (raw_event.pid as u64);
                let event: ReadEvent = raw_event.into();
                let mut map = map_clone.lock().await;
                map.insert(tpid_gid, event);
                Ok(())
            },
        )
        .await;
    });

    let map_clone = read_event_map.clone();
    tokio::task::spawn(async move {
        let _ = handle_tracepoint(
            "stalk_read_exit",
            ["syscalls", "sys_exit_read"],
            "READ_EXIT_EVENTS",
            async move |raw_event: RawReadEventExit| {
                let tpid_gid = ((raw_event.gid as u64) << 32) | (raw_event.pid as u64);
                let mut map = map_clone.lock().await;
                if let Some(mut read_event) = map.remove(&tpid_gid) {
                    read_event.end_time = Some(tokio::time::Instant::now());
                    let duration = read_event.start_time.elapsed();
                    println!("{}, duration: {:?}", read_event, duration);
                }
                Ok(())
            },
        )
        .await;
    });

    tokio::task::spawn(async move {
        let _ = handle_tracepoint(
            "stalk_openat",
            ["syscalls", "sys_enter_openat"],
            "OPENAT_EVENTS",
            async move |raw_event: RawOpenatEvent| {
                let event: OpenatEvent = raw_event.into();
                println!("{}", event);
                Ok(())
            },
        )
        .await;
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

async fn handle_tracepoint<F: event::RawEvent>(
    program: &str,
    attach_point: [&str; 2],
    event_map: &str,
    func: impl AsyncFn(F) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/stalk"
    )))?;
    init_ebpf(&mut ebpf)?;
    let program: &mut TracePoint = ebpf.program_mut(program).unwrap().try_into()?;
    program.load()?;
    program.attach(attach_point[0], attach_point[1])?;
    let mut perf_array = PerfEventArray::try_from(
        ebpf.map_mut(event_map)
            .ok_or(anyhow::anyhow!("Failed to find map {}", event_map))?,
    )?;
    let array_buf = perf_array.open(0, None)?;
    let mut async_array_buf = AsyncFd::with_interest(array_buf, tokio::io::Interest::READABLE)?;
    let mut buffer = vec![BytesMut::with_capacity(size_of::<F>())];
    loop {
        let mut guard = async_array_buf.readable_mut().await?;
        let events = guard.get_inner_mut().read_events(&mut buffer)?;
        guard.clear_ready();
        for i in 0..events.read {
            let buf = &buffer[i];
            let ptr = buf.as_ptr() as *const F;
            let raw_event = unsafe { ptr.read_unaligned() };
            func(raw_event).await?;
        }
    }
}
