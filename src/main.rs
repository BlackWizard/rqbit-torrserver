use librqbit::Session;
use rqbit_torrserver::{AppState, create_router};
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber - default to warn level
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true).with_level(true))
        .with(filter)
        .init();

    // 1. Initialize the rqbit session
    let session = Session::new("/tmp/downloads".into()).await.unwrap();

    // 2. Create shutdown channel
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    // 3. Create application state
    let state = Arc::new(AppState::new(session, shutdown_tx));

    // 4. Define the TorrServer-compatible router
    let app = create_router(state);

    // 5. Start the bridge on TorrServer's default port
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8090").await.unwrap();
    println!("TorrServer bridge for rqbit running on port 8090");

    // 6. Serve with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
            println!("Shutting down...");
        })
        .await
        .unwrap();
}
