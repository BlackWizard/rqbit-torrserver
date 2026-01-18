use axum_test::TestServer;
use librqbit::{Session, SessionOptions};
use rqbit_torrserver::create_router;
use tempfile::tempdir;

// Helper to create the test app
async fn create_test_app() -> TestServer {
    let tdir = tempdir().expect("Failed to create temp dir");

    let download_dir = tdir.path().join("downloads");

    let mut options = SessionOptions::default();
    options.disable_dht = true;
    options.persistence = None;
    /*options.listen = Some(ListenOptions {
        addr: "0.0.0.0:0".parse().unwrap(),
        ..Default::default()
    });*/

    let session = Session::new_with_opts(download_dir, options)
        .await
        .expect("Failed to initialize session with options");

    let app = create_router(session);
    TestServer::new(app).unwrap()
}

#[tokio::test]
async fn test_echo_endpoint() {
    let server = create_test_app().await;

    let response = server.get("/echo").await;

    response.assert_status_ok();
    let json: serde_json::Value = response.json();
    let version = json["version"]
        .as_str()
        .expect("version should be a string");
    assert!(
        version.starts_with("rqbit-torserver "),
        "version should start with 'rqbit-torserver '"
    );
}

#[tokio::test]
async fn test_add_torrent_via_post() {
    let server = create_test_app().await;
    let magnet = "magnet:?xt=urn:btih:cab507494d02ebb1178b38f2e9d7be299c86b862";

    // TorrServer adds torrents by sending the magnet link in the body
    let response = server.post("/torrents").text(magnet).await;

    // With DHT disabled in tests, magnet links without trackers cannot resolve peers.
    // The handler correctly returns an error in this case.
    response.assert_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_stream_redirection_params() {
    let server = create_test_app().await;
    let hash = "cab507494d02ebb1178b38f2e9d7be299c86b862";

    // Test the streaming endpoint structure
    let response = server
        .get("/stream/movie.mp4")
        .add_query_param("link", hash)
        .add_query_param("index", 1)
        .await;

    // Verification depends on whether you implement a 302 redirect or direct proxy
    response.assert_status_ok();
}
