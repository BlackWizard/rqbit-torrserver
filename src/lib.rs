use axum::{
    Router,
    routing::{get, post},
};
use librqbit::{Api, Session};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, oneshot};
use tower_http::cors::{Any, CorsLayer};
// use tower_http::services::ServeDir;

pub mod handlers;
pub mod models;

/// Stored metadata for a torrent (from add request)
#[derive(Clone, Default)]
pub struct TorrentMetadata {
    pub title: String,
    pub poster: String,
    pub category: String,
    pub data: String,
    pub timestamp: i64,
}

/// Application state shared across handlers
pub struct AppState {
    pub session: Arc<Session>,
    pub api: Api,
    pub shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    /// Metadata storage keyed by info_hash (lowercase)
    pub torrent_metadata: RwLock<HashMap<String, TorrentMetadata>>,
}

impl AppState {
    pub fn new(session: Arc<Session>, shutdown_tx: oneshot::Sender<()>) -> Self {
        let api = Api::new(session.clone(), None);
        Self {
            session,
            api,
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            torrent_metadata: RwLock::new(HashMap::new()),
        }
    }
}

/// Create the TorrServer-compatible router
pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

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
        //.nest_service("/", ServeDir::new("web"))
        .fallback(handlers::static_handler)
        .layer(cors)
        .with_state(state)
}

/// Create router for testing (without shutdown capability)
pub fn create_test_router(session: Arc<Session>) -> Router {
    let (tx, _rx) = oneshot::channel();
    let state = Arc::new(AppState::new(session, tx));
    create_router(state)
}
