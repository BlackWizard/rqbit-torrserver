// UDP tracker client for opentor.org retracker
use std::net::SocketAddr;
use tokio::net::UdpSocket;

const CONNECTION_ID_MAGIC: u64 = 0x41727101980;
const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;

pub async fn announce_to_udp_tracker(
    tracker_addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: u32,
) -> Result<Vec<SocketAddr>, String> {
    // Bind to any available port
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

    // Step 1: Connect request
    println!("[UDP_TRACKER] Sending connect request to {}", tracker_addr);
    let connection_id = udp_connect(&socket, tracker_addr).await?;
    println!("[UDP_TRACKER] Received connection_id: 0x{:x}", connection_id);

    // Step 2: Announce request
    println!("[UDP_TRACKER] Sending announce request");
    let peers = udp_announce(
        &socket,
        tracker_addr,
        connection_id,
        info_hash,
        peer_id,
        port,
        uploaded,
        downloaded,
        left,
        event,
    )
    .await?;

    println!("[UDP_TRACKER] Announce successful");
    Ok(peers)
}

async fn udp_connect(socket: &UdpSocket, tracker_addr: SocketAddr) -> Result<u64, String> {
    let transaction_id: u32 = rand::random();

    // Build connect request
    let mut request = Vec::new();
    request.extend_from_slice(&CONNECTION_ID_MAGIC.to_be_bytes());
    request.extend_from_slice(&ACTION_CONNECT.to_be_bytes());
    request.extend_from_slice(&transaction_id.to_be_bytes());

    // Send request
    socket
        .send_to(&request, tracker_addr)
        .await
        .map_err(|e| format!("Failed to send connect request: {}", e))?;

    // Receive response
    let mut response = vec![0u8; 1024];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        socket.recv_from(&mut response),
    )
    .await
    .map_err(|_| "Connect timeout".to_string())?
    .map_err(|e| format!("Failed to receive connect response: {}", e))?;

    if len < 16 {
        return Err(format!("Connect response too short: {} bytes", len));
    }

    // Parse response
    let resp_action = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
    let resp_transaction_id =
        u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    let connection_id = u64::from_be_bytes([
        response[8],
        response[9],
        response[10],
        response[11],
        response[12],
        response[13],
        response[14],
        response[15],
    ]);

    if resp_action != ACTION_CONNECT {
        return Err(format!("Invalid action in response: {}", resp_action));
    }

    if resp_transaction_id != transaction_id {
        return Err(format!(
            "Transaction ID mismatch: expected {}, got {}",
            transaction_id, resp_transaction_id
        ));
    }

    Ok(connection_id)
}

#[allow(clippy::too_many_arguments)]
async fn udp_announce(
    socket: &UdpSocket,
    tracker_addr: SocketAddr,
    connection_id: u64,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: u32,
) -> Result<Vec<SocketAddr>, String> {
    let transaction_id: u32 = rand::random();
    let key: u32 = rand::random();

    // Build announce request
    let mut request = Vec::new();
    request.extend_from_slice(&connection_id.to_be_bytes());
    request.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    request.extend_from_slice(&transaction_id.to_be_bytes());
    request.extend_from_slice(&info_hash);
    request.extend_from_slice(&peer_id);
    request.extend_from_slice(&downloaded.to_be_bytes());
    request.extend_from_slice(&left.to_be_bytes());
    request.extend_from_slice(&uploaded.to_be_bytes());
    request.extend_from_slice(&event.to_be_bytes());
    request.extend_from_slice(&0u32.to_be_bytes()); // IP address (0 = default)
    request.extend_from_slice(&key.to_be_bytes());
    request.extend_from_slice(&(-1i32).to_be_bytes()); // num_want (-1 = default)
    request.extend_from_slice(&port.to_be_bytes());

    // Send request
    socket
        .send_to(&request, tracker_addr)
        .await
        .map_err(|e| format!("Failed to send announce request: {}", e))?;

    // Receive response
    let mut response = vec![0u8; 16384];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        socket.recv_from(&mut response),
    )
    .await
    .map_err(|_| "Announce timeout".to_string())?
    .map_err(|e| format!("Failed to receive announce response: {}", e))?;

    if len < 20 {
        return Err(format!("Announce response too short: {} bytes", len));
    }

    // Parse response
    let resp_action = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
    let resp_transaction_id =
        u32::from_be_bytes([response[4], response[5], response[6], response[7]]);

    if resp_action == 3 {
        // Error action
        let error_msg = String::from_utf8_lossy(&response[8..len]);
        return Err(format!("Tracker error: {}", error_msg));
    }

    if resp_action != ACTION_ANNOUNCE {
        return Err(format!("Invalid action in response: {}", resp_action));
    }

    if resp_transaction_id != transaction_id {
        return Err(format!(
            "Transaction ID mismatch: expected {}, got {}",
            transaction_id, resp_transaction_id
        ));
    }

    let interval = u32::from_be_bytes([response[8], response[9], response[10], response[11]]);
    let leechers = u32::from_be_bytes([response[12], response[13], response[14], response[15]]);
    let seeders = u32::from_be_bytes([response[16], response[17], response[18], response[19]]);

    println!(
        "[UDP_TRACKER] Interval: {}s, Leechers: {}, Seeders: {}",
        interval, leechers, seeders
    );

    // Parse peers (6 bytes each: 4 bytes IP + 2 bytes port)
    let mut peers = Vec::new();
    let peer_data = &response[20..len];
    for chunk in peer_data.chunks_exact(6) {
        let ip = std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        let port = u16::from_be_bytes([chunk[4], chunk[5]]);
        peers.push(SocketAddr::new(std::net::IpAddr::V4(ip), port));
    }

    Ok(peers)
}
