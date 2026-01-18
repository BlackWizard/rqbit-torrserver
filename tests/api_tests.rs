use axum_test::TestServer;
use librqbit::{Session, SessionOptions};
use rqbit_torrserver::create_test_router;
use tempfile::tempdir;

// Helper to create the test app
async fn create_test_app() -> TestServer {
    let tdir = tempdir().expect("Failed to create temp dir");

    let download_dir = tdir.path().join("downloads");

    let mut options = SessionOptions::default();
    options.disable_dht = true;
    options.persistence = None;

    let session = Session::new_with_opts(download_dir, options)
        .await
        .expect("Failed to initialize session with options");

    let app = create_test_router(session);
    TestServer::new(app).unwrap()
}

#[tokio::test]
async fn test_echo_endpoint() {
    let server = create_test_app().await;

    let response = server.get("/echo").await;

    response.assert_status_ok();
    // TorrServer /echo returns plain text
    let text = response.text();
    assert!(
        text.starts_with("rqbit-torserver "),
        "version should start with 'rqbit-torserver '"
    );
}

#[tokio::test]
async fn test_torrents_list() {
    let server = create_test_app().await;

    let response = server
        .post("/torrents")
        .json(&serde_json::json!({"action": "list"}))
        .await;

    response.assert_status_ok();
    let json: serde_json::Value = response.json();
    assert!(json.is_array(), "list should return an array");
}

#[tokio::test]
async fn test_torrents_add_without_dht() {
    let server = create_test_app().await;

    let response = server
        .post("/torrents")
        .json(&serde_json::json!({
            "action": "add",
            "link": "magnet:?xt=urn:btih:cab507494d02ebb1178b38f2e9d7be299c86b862"
        }))
        .await;

    // With DHT disabled in tests, magnet links without trackers cannot resolve peers.
    response.assert_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_settings_get() {
    let server = create_test_app().await;

    let response = server
        .post("/settings")
        .json(&serde_json::json!({"action": "get"}))
        .await;

    response.assert_status_ok();
    let json: serde_json::Value = response.json();
    assert!(json.is_object(), "settings should return an object");
}

#[tokio::test]
async fn test_settings_def() {
    let server = create_test_app().await;

    let response = server
        .post("/settings")
        .json(&serde_json::json!({"action": "def"}))
        .await;

    response.assert_status_ok();
}

#[tokio::test]
async fn test_stat_endpoint() {
    let server = create_test_app().await;

    let response = server.get("/stat").await;

    response.assert_status_ok();
    let text = response.text();
    assert!(
        text.contains("Torrents:"),
        "stat should contain torrent count"
    );
}

#[tokio::test]
async fn test_viewed_list() {
    let server = create_test_app().await;

    let response = server
        .post("/viewed")
        .json(&serde_json::json!({"action": "list"}))
        .await;

    response.assert_status_ok();
    let json: serde_json::Value = response.json();
    assert!(json.is_array(), "viewed list should return an array");
}

#[tokio::test]
async fn test_stream_with_nonexistent_torrent() {
    let server = create_test_app().await;
    let hash = "cab507494d02ebb1178b38f2e9d7be299c86b862";

    // Test the streaming endpoint with a torrent that doesn't exist
    // It should try to add it and fail (no DHT)
    let response = server
        .get("/stream/movie.mp4")
        .add_query_param("link", hash)
        .add_query_param("index", "0")
        .await;

    // Should fail because torrent doesn't exist and can't be added without DHT
    response.assert_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
}
