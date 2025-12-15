use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, serve::Serve};
use tokio::sync::RwLock;
pub type Server = Serve<tokio::net::TcpListener, axum::Router, axum::Router>;

use crate::agent::state::{
    TuiState, get_execve_logs, get_net_logs, get_openat_logs, get_read_logs,
};

pub async fn web_server(shared_state: Arc<RwLock<TuiState>>, port: u16) -> anyhow::Result<Server> {
    let app = axum::Router::new()
        .route("/state", get(get_state))
        .route("/logs/execve", get(get_execve_logs))
        .route("/logs/read", get(get_read_logs))
        .route("/logs/openat", get(get_openat_logs))
        .route("/logs/net", get(get_net_logs))
        // .route("/rank/execve", _)
        // .route("/rank/read", _)
        // .route("/rank/openat", _)
        // .route("/rank/net", _)
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
