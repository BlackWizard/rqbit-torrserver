use axum::{
    routing::{get, post},
    Router,
};
use librqbit::{Api, Session};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

pub mod handlers;
pub mod models;

/// Application state shared across handlers
pub struct AppState {
    pub session: Arc<Session>,
    pub api: Api,
    pub shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl AppState {
    pub fn new(session: Arc<Session>, shutdown_tx: oneshot::Sender<()>) -> Self {
        let api = Api::new(session.clone(), None);
        Self {
            session,
            api,
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
        }
    }
}

/// Create the TorrServer-compatible router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Core TorrServer API endpoints
        .route("/echo", get(handlers::echo_handler))
        .route("/torrents", post(handlers::torrents_handler))
        .route("/stream/*path", get(handlers::stream_handler))
        .route("/play/{hash}/{id}", get(handlers::play_handler))
        .route("/settings", post(handlers::settings_handler))
        .route("/shutdown", get(handlers::shutdown_handler))
        .route("/viewed", post(handlers::viewed_handler))
        .route("/cache", post(handlers::cache_handler))
        .route("/stat", get(handlers::stat_handler))
        .route("/playlist", get(handlers::playlist_handler))
        .with_state(state)
}

/// Create router for testing (without shutdown capability)
pub fn create_test_router(session: Arc<Session>) -> Router {
    let (tx, _rx) = oneshot::channel();
    let state = Arc::new(AppState::new(session, tx));
    create_router(state)
}
