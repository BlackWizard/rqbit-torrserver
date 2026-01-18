use librqbit::Session;
use rqbit_torrserver::create_router;

#[tokio::main]
async fn main() {
    // 1. Initialize the rqbit session
    let session = Session::new("/tmp/downloads".into()).await.unwrap();

    // 2. Define the TorrServer-compatible router
    let torr_router = create_router(session);

    // 3. Start the bridge on TorrServer's default port
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8090").await.unwrap();
    println!("TorrServer bridge for rqbit running on port 8090");
    axum::serve(listener, torr_router).await.unwrap();
}
