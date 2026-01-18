use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use librqbit::{AddTorrent, Session};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct TorrentAction {
    link: String, // TorrServer uses 'link' for magnet/hash
    index: Option<usize>,
}

#[derive(Serialize)]
pub struct EchoResponse {
    version: String,
}

pub async fn echo_handler() -> Json<EchoResponse> {
    // Use git describe if available, otherwise fall back to CARGO_PKG_VERSION
    let version = option_env!("VERGEN_GIT_DESCRIBE")
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    Json(EchoResponse {
        version: format!("rqbit-torserver {}", version),
    })
}

pub async fn add_torrent_handler(
    State(session): State<Arc<Session>>,
    body: String, // TorrServer often sends magnet links in the body
) -> Result<String, impl IntoResponse> {
    let add_torrent = AddTorrent::from_url(&body);
    session
        .add_torrent(add_torrent, None)
        .await
        .map(|_| "OK".to_string())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

pub async fn stream_handler(
    State(_session): State<Arc<Session>>,
    Query(params): Query<TorrentAction>,
) -> String {
    // TorrServer link: /stream/fname?link=HASH&index=ID
    // In a real bridge, you would redirect to rqbit's native stream:
    // http://IP:3030/torrents/<id>/stream/<file_id>
    format!(
        "Redirecting to rqbit stream for hash {} file index {}",
        params.link,
        params.index.unwrap_or(0)
    )
}
