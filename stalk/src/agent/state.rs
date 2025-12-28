use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Query, State},
    response::IntoResponse,
};
use serde::Deserialize;
use tokio::sync::{RwLock, mpsc};

use crate::event::{Event, ExecveEvent, ExitEvent, OpenatEvent, ReadEvent, XdpEvent};
#[derive(Debug)]
pub enum StalkEvent {
    Execve(ExecveEvent),
    Exit(ExitEvent),
    Read(ReadEvent),
    Openat(OpenatEvent),
    Xdp(XdpEvent),
}

pub struct TuiState {
    /// Path -> count
    pub execve_rank: HashMap<String, usize>,
    pub execve_logs: Vec<String>,
    /// Error code -> count
    pub exit_rank: HashMap<u64, usize>,
    pub exit_logs: Vec<String>,
    /// Pid -> duration in us
    pub read_rank: HashMap<u32, u64>,
    pub read_logs: Vec<String>,
    /// Path -> count
    pub openat_rank: HashMap<String, usize>,
    pub openat_logs: Vec<String>,
    /// IP -> count
    pub net_rank: HashMap<[u8; 4], usize>,
    pub net_logs: Vec<String>,
    pub start_time: tokio::time::Instant,
}

fn update_state(state: &mut TuiState, event: StalkEvent) {
    match event {
        StalkEvent::Execve(ev) => {
            *state.execve_rank.entry(ev.filename.clone()).or_insert(0) += 1;
            state.execve_logs.push(ev.to_string());
        }
        StalkEvent::Exit(ev) => {
            *state.exit_rank.entry(ev.exit_code).or_insert(0) += 1;
            state.exit_logs.push(ev.to_string());
        }
        StalkEvent::Read(ev) => {
            let duration = ev
                .end_time
                .map(|t| t.duration_since(ev.start_time).as_micros())
                .unwrap_or_default();
            *state.read_rank.entry(ev.pid()).or_insert(0) += duration as u64;
            state.read_logs.push(ev.to_string());
        }
        StalkEvent::Openat(ev) => {
            *state.openat_rank.entry(ev.filename.clone()).or_insert(0) += 1;
            state.openat_logs.push(ev.to_string());
        }
        StalkEvent::Xdp(ev) => {
            *state.net_rank.entry(ev.source_addr).or_insert(0) += 1;
            state.net_logs.push(ev.to_string());
        }
    }
}

pub fn run_agent(mut rx: mpsc::Receiver<StalkEvent>, shared_state: Arc<RwLock<TuiState>>) {
    tokio::task::spawn(async move {
        loop {
            if let Some(event) = rx.recv().await {
                let mut state = shared_state.write().await;
                update_state(&mut state, event);
            }
        }
    });
}

impl Default for TuiState {
    fn default() -> Self {
        TuiState {
            execve_rank: HashMap::new(),
            execve_logs: Vec::new(),
            exit_rank: HashMap::new(),
            exit_logs: Vec::new(),
            read_rank: HashMap::new(),
            read_logs: Vec::new(),
            openat_rank: HashMap::new(),
            openat_logs: Vec::new(),
            net_rank: HashMap::new(),
            net_logs: Vec::new(),
            start_time: tokio::time::Instant::now(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct QueryParam {
    pub num: Option<usize>,
}

pub async fn get_execve_logs(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
    Query(param): Query<QueryParam>,
) -> anyhow::Result<impl IntoResponse, String> {
    let logs = shared_state
        .read()
        .await
        .execve_logs
        .clone()
        .into_iter()
        .take(param.num.unwrap_or(100))
        .collect::<Vec<_>>();
    Ok(axum::Json(logs))
}

pub async fn get_exit_logs(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
    Query(param): Query<QueryParam>,
) -> anyhow::Result<impl IntoResponse, String> {
    let logs = shared_state
        .read()
        .await
        .exit_logs
        .clone()
        .into_iter()
        .take(param.num.unwrap_or(100))
        .collect::<Vec<_>>();
    Ok(axum::Json(logs))
}

pub async fn get_read_logs(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
    Query(param): Query<QueryParam>,
) -> anyhow::Result<impl IntoResponse, String> {
    let logs = shared_state
        .read()
        .await
        .read_logs
        .clone()
        .into_iter()
        .take(param.num.unwrap_or(100))
        .collect::<Vec<_>>();
    Ok(axum::Json(logs))
}

pub async fn get_openat_logs(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
    Query(param): Query<QueryParam>,
) -> anyhow::Result<impl IntoResponse, String> {
    let logs = shared_state
        .read()
        .await
        .openat_logs
        .clone()
        .into_iter()
        .take(param.num.unwrap_or(100))
        .collect::<Vec<_>>();
    Ok(axum::Json(logs))
}

pub async fn get_net_logs(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
    Query(param): Query<QueryParam>,
) -> anyhow::Result<impl IntoResponse, String> {
    let logs = shared_state
        .read()
        .await
        .net_logs
        .clone()
        .into_iter()
        .take(param.num.unwrap_or(100))
        .collect::<Vec<_>>();
    Ok(axum::Json(logs))
}

pub async fn get_execve_rank(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
    Query(param): Query<QueryParam>,
) -> anyhow::Result<impl IntoResponse, String> {
    let rank = shared_state.read().await.execve_rank.clone();
    let mut sorted: Vec<_> = rank.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(axum::Json(
        sorted
            .into_iter()
            .take(param.num.unwrap_or(10))
            .collect::<Vec<_>>(),
    ))
}

pub async fn get_exit_rank(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
    Query(param): Query<QueryParam>,
) -> anyhow::Result<impl IntoResponse, String> {
    let rank = shared_state.read().await.exit_rank.clone();
    let mut sorted: Vec<_> = rank.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(axum::Json(
        sorted
            .into_iter()
            .take(param.num.unwrap_or(10))
            .collect::<Vec<_>>(),
    ))
}

pub async fn get_read_rank(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
    Query(param): Query<QueryParam>,
) -> anyhow::Result<impl IntoResponse, String> {
    let rank = shared_state.read().await.read_rank.clone();
    let mut sorted: Vec<_> = rank.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(axum::Json(
        sorted
            .into_iter()
            .take(param.num.unwrap_or(10))
            .collect::<Vec<_>>(),
    ))
}

pub async fn get_openat_rank(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
    Query(param): Query<QueryParam>,
) -> anyhow::Result<impl IntoResponse, String> {
    let rank = shared_state.read().await.openat_rank.clone();
    let mut sorted: Vec<_> = rank.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(axum::Json(
        sorted
            .into_iter()
            .take(param.num.unwrap_or(10))
            .collect::<Vec<_>>(),
    ))
}

pub async fn get_net_rank(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
    Query(param): Query<QueryParam>,
) -> anyhow::Result<impl IntoResponse, String> {
    let rank = shared_state.read().await.net_rank.clone();
    let mut sorted: Vec<_> = rank.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(axum::Json(
        sorted
            .into_iter()
            .take(param.num.unwrap_or(10))
            .collect::<Vec<_>>(),
    ))
}
