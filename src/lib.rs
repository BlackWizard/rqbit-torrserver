use axum::{
    Router,
    routing::{get, post},
};
use librqbit::Session;
use std::sync::Arc;

pub mod handlers;

pub fn create_router(session: Arc<Session>) -> Router {
    Router::new()
        .route("/echo", get(crate::handlers::echo_handler))
        .route("/torrents", post(crate::handlers::add_torrent_handler))
        .route("/stream/*path", get(crate::handlers::stream_handler))
        .with_state(session)
}
