use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get};
use tokio::sync::RwLock;

use crate::agent::state::TuiState;

pub async fn web_server(shared_state: Arc<RwLock<TuiState>>, port: u16) -> anyhow::Result<()> {
    let app = axum::Router::new()
        .route("/state", get(get_state))
        // .route("/logs/execve", _)
        // .route("/logs/read", _)
        // .route("/logs/openat", _)
        // .route("/logs/net", _);
        // .route("/rank/execve", _)
        // .route("/rank/read", _)
        // .route("/rank/openat", _)
        // .route("/rank/net", _)
        .with_state(shared_state);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let server = axum::serve(listener, app).await;
    Ok(())
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
