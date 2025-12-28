use std::{collections::HashMap, sync::Arc};

use aya::{
    maps::RingBuf,
    programs::{TracePoint, Xdp, XdpFlags},
};
use log::warn;
use stalk_common::{
    RawExecveEvent, RawExitEvent, RawOpenatEvent, RawReadEvent, RawReadEventExit, RawXdpEvent,
};
use tokio::{
    io::unix::AsyncFd,
    sync::{Mutex, RwLock, mpsc},
};

use crate::{
    agent::{
        server::Server,
        state::{StalkEvent, TuiState},
    },
    config::{StalkConfig, StalkItem},
    event::{ExecveEvent, ExitEvent, OpenatEvent, ReadEvent, XdpEvent},
};
pub type EventSender = mpsc::Sender<StalkEvent>;

pub async fn stalk(config: StalkConfig) -> anyhow::Result<Server> {
    let (tx, rx) = mpsc::channel::<StalkEvent>(1024);
    let shared_state = Arc::new(RwLock::new(TuiState {
        start_time: tokio::time::Instant::now(),
        ..Default::default()
    }));
    crate::agent::state::run_agent(rx, shared_state.clone());
    for item in config.items {
        match item {
            StalkItem::Execve => {
                stalk_execve(tx.clone());
            }
            StalkItem::Exit => {
                stalk_exit(tx.clone());
            }
            StalkItem::Openat => {
                stalk_openat(tx.clone());
            }
            StalkItem::Read => {
                stalk_read(tx.clone());
            }
            StalkItem::Net(interface) => {
                stalk_net(tx.clone(), interface);
            }
        }
    }
    crate::agent::server::web_server(shared_state, config.port).await
}

pub fn stalk_execve(tx: EventSender) {
    tokio::task::spawn(async move {
        let _ = handle_tracepoint(
            "stalk_execve",
            ("syscalls", "sys_enter_execve"),
            "EXECVE_EVENTS",
            async move |raw_event: RawExecveEvent| {
                let event: ExecveEvent = raw_event.into();
                tx.send(StalkEvent::Execve(event)).await.unwrap();
                Ok(())
            },
        )
        .await;
    });
}

pub fn stalk_exit(tx: EventSender) {
    tokio::task::spawn(async move {
        let _ = handle_tracepoint(
            "stalk_exit_group",
            ("syscalls", "sys_enter_exit_group"),
            "TRACEPOINT_EXIT_EVENTS",
            async move |raw_event: RawExitEvent| {
                let event: ExitEvent = raw_event.into();
                tx.send(StalkEvent::Exit(event)).await.unwrap();
                Ok(())
            },
        )
        .await;
    });
}

pub fn stalk_read(tx: EventSender) {
    let read_event_map = Arc::new(Mutex::new(HashMap::new()));
    let map_clone = read_event_map.clone();
    tokio::task::spawn(async move {
        let _ = handle_tracepoint(
            "stalk_read",
            ("syscalls", "sys_enter_read"),
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
            ("syscalls", "sys_exit_read"),
            "READ_EXIT_EVENTS",
            async move |raw_event: RawReadEventExit| {
                let tpid_gid = ((raw_event.gid as u64) << 32) | (raw_event.pid as u64);
                let mut map = map_clone.lock().await;
                if let Some(mut read_event) = map.remove(&tpid_gid) {
                    read_event.end_time = Some(tokio::time::Instant::now());
                    tx.send(StalkEvent::Read(read_event)).await.unwrap();
                }
                Ok(())
            },
        )
        .await;
    });
}

pub fn stalk_openat(tx: EventSender) {
    tokio::task::spawn(async move {
        let _ = handle_tracepoint(
            "stalk_openat",
            ("syscalls", "sys_enter_openat"),
            "OPENAT_EVENTS",
            async move |raw_event: RawOpenatEvent| {
                let event: OpenatEvent = raw_event.into();
                tx.send(StalkEvent::Openat(event)).await.unwrap();
                Ok(())
            },
        )
        .await;
    });
}

pub fn stalk_net(tx: EventSender, interface: String) {
    tokio::task::spawn(async move {
        let _ = handle_xdp(
            "stalk_xdp",
            (interface.as_str(), XdpFlags::default()),
            "XDP_EVENTS",
            async move |raw_event: RawXdpEvent| {
                let event: XdpEvent = raw_event.into();
                tx.send(StalkEvent::Xdp(event)).await.unwrap();
                Ok(())
            },
        )
        .await;
    });
}

async fn handle_tracepoint<F: crate::event::RawEvent>(
    program: &str,
    attach_point: (&str, &str),
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
    program.attach(attach_point.0, attach_point.1)?;
    let ring_buf = RingBuf::try_from(
        ebpf.map_mut(event_map)
            .ok_or(anyhow::anyhow!("Failed to find map {}", event_map))?,
    )?;
    let mut async_array_buf = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;
    loop {
        let mut guard = async_array_buf.readable_mut().await?;
        let events = guard.get_inner_mut();
        while let Some(item) = events.next() {
            let ptr = item.as_ptr() as *const F;
            let raw_event = unsafe { ptr.read_unaligned() };
            func(raw_event).await?;
        }
        guard.clear_ready();
    }
}

async fn handle_xdp<F: crate::event::RawEvent>(
    program: &str,
    attach_point: (&str, XdpFlags),
    event_map: &str,
    func: impl AsyncFn(F) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/stalk"
    )))?;
    init_ebpf(&mut ebpf)?;
    let program: &mut Xdp = ebpf.program_mut(program).unwrap().try_into()?;
    program.load()?;
    program.attach(attach_point.0, attach_point.1)?;
    let ring_buf = RingBuf::try_from(
        ebpf.map_mut(event_map)
            .ok_or(anyhow::anyhow!("Failed to find map {}", event_map))?,
    )?;
    let mut async_array_buf = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;
    loop {
        let mut guard = async_array_buf.readable_mut().await?;
        let events = guard.get_inner_mut();
        while let Some(item) = events.next() {
            let ptr = item.as_ptr() as *const F;
            let raw_event = unsafe { ptr.read_unaligned() };
            func(raw_event).await?;
        }
        guard.clear_ready();
    }
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
