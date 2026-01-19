use axum::{
    Router,
    body::Body,
    http::{Request, Response, header::HeaderValue},
    routing::{get, post},
};
use librqbit::{Api, Session};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, oneshot};
use tower_http::cors::{Any, CorsLayer};

pub mod handlers;
pub mod models;
pub mod udp_tracker;

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

/// Middleware to add Access-Control-Allow-Private-Network header for Chrome
async fn add_private_network_header(
    request: Request<Body>,
    next: axum::middleware::Next,
) -> Response<Body> {
    let mut response = next.run(request).await;

    // Add the private network access header
    response.headers_mut().insert(
        "Access-Control-Allow-Private-Network",
        HeaderValue::from_static("true"),
    );

    response
}

/// Create the TorrServer-compatible router
pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any)
        .max_age(std::time::Duration::from_secs(3600));

    Router::new()
        // Core TorrServer API endpoints
        .route("/echo", get(self::handlers::echo_handler))
        .route("/torrents", post(self::handlers::torrents_handler))
        .route("/stream/{*path}", get(self::handlers::stream_handler))
        .route("/play/{hash}/{id}", get(self::handlers::play_handler))
        .route("/settings", post(self::handlers::settings_handler))
        .route("/shutdown", get(self::handlers::shutdown_handler))
        .route("/viewed", post(self::handlers::viewed_handler))
        .route("/cache", post(self::handlers::cache_handler))
        .route("/stat", get(self::handlers::stat_handler))
        .route("/playlist", get(self::handlers::playlist_handler))
        // Retracker endpoint - fetches peers from opentor.org
        .route("/announce", get(self::handlers::announce_handler))
        .fallback(self::handlers::static_handler)
        .layer(cors)
        .layer(axum::middleware::from_fn(add_private_network_header))
        .with_state(state)
}

/// Create router for testing (without shutdown capability)
pub fn create_test_router(session: Arc<Session>) -> Router {
    let (tx, _rx) = oneshot::channel();
    let state = Arc::new(AppState::new(session, tx));
    create_router(state)
}
