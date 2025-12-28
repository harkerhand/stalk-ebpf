use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, serve::Serve};
use tokio::sync::RwLock;
pub type Server = Serve<tokio::net::TcpListener, axum::Router, axum::Router>;

use crate::agent::state::{
    TuiState, get_execve_logs, get_execve_rank, get_net_logs, get_net_rank, get_openat_logs,
    get_openat_rank, get_read_logs, get_read_rank, get_exit_logs, get_exit_rank,
};

pub async fn web_server(shared_state: Arc<RwLock<TuiState>>, port: u16) -> anyhow::Result<Server> {
    let app = axum::Router::new()
        .route("/state", get(get_state))
        .route("/logs/execve", get(get_execve_logs))
        .route("/logs/exit", get(get_exit_logs))
        .route("/logs/read", get(get_read_logs))
        .route("/logs/openat", get(get_openat_logs))
        .route("/logs/net", get(get_net_logs))
        .route("/rank/execve", get(get_execve_rank))
        .route("/rank/exit", get(get_exit_rank))
        .route("/rank/read", get(get_read_rank))
        .route("/rank/openat", get(get_openat_rank))
        .route("/rank/net", get(get_net_rank))
        .with_state(shared_state);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    Ok(axum::serve(listener, app))
}

async fn get_state(
    State(shared_state): State<Arc<RwLock<TuiState>>>,
) -> anyhow::Result<impl IntoResponse, String> {
    let start_time = shared_state.read().await.start_time;
    let uptime = tokio::time::Instant::now().duration_since(start_time);
    let hours = uptime.as_secs() / 3600;
    let minutes = (uptime.as_secs() % 3600) / 60;
    let seconds = uptime.as_secs() % 60;
    let uptime_str = format!("{:02}:{:02}:{:02}", hours, minutes, seconds);
    let response = serde_json::json!({
        "uptime": uptime_str,
    });
    Ok(axum::Json(response))
}
