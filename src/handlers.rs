use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use librqbit::{AddTorrent, AddTorrentOptions, api::TorrentIdOrHash};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use crate::models::*;
use crate::{AppState, TorrentMetadata};

use rust_embed::RustEmbed;
use serde::Deserialize;

#[derive(RustEmbed)]
#[folder = "web/"]
struct Assets;

/// Parse JSON from body regardless of Content-Type header.
/// TorrServer clients often send JSON with Content-Type: application/x-www-form-urlencoded
fn parse_json<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, (StatusCode, String)> {
    serde_json::from_slice(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)))
}

pub async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');

    // Default to index.html for root or SPA routing
    let path = if path.is_empty() { "index.html" } else { path };

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(Body::from(content.data))
                .unwrap()
        }
        None => {
            // Optional: fallback to index.html for SPA routing
            if path != "index.html" {
                return Box::pin(static_handler(Uri::from_static("/")))
                    .await
                    .into_response();
            }
            (StatusCode::NOT_FOUND, "404 Not Found").into_response()
        }
    }
}

// ============================================================================
// GET /echo - Returns server version as plain text
// ============================================================================
pub async fn echo_handler() -> impl IntoResponse {
    let version = option_env!("VERGEN_GIT_DESCRIBE").unwrap_or(env!("CARGO_PKG_VERSION"));
    format!("rqbit-torserver {}", version)
}

// ============================================================================
// POST /torrents - Handle torrent operations based on action
// ============================================================================
pub async fn torrents_handler(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let req: TorrentsRequest = parse_json(&body)?;
    match req.action.as_str() {
        "add" => torrents_add(state, req).await,
        "get" => torrents_get(state, req).await,
        "set" => torrents_set(state, req).await,
        "rem" | "drop" => torrents_remove(state, req).await,
        "list" => torrents_list(state).await,
        "wipe" => torrents_wipe(state).await,
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("Unknown action: {}", req.action),
        )),
    }
}

async fn torrents_add(
    state: Arc<AppState>,
    req: TorrentsRequest,
) -> Result<Response, (StatusCode, String)> {
    let link = req.link.ok_or((
        StatusCode::BAD_REQUEST,
        "link is required for add action".to_string(),
    ))?;

    // Extract hash from magnet link for immediate response
    let hash = extract_hash(&link);
    let title = req.title.clone().unwrap_or_default();
    let poster = req.poster.clone().unwrap_or_default();
    let category = req.category.clone().unwrap_or_default();
    let data = req.data.clone().unwrap_or_default();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Store metadata for later retrieval
    {
        let metadata = TorrentMetadata {
            title: title.clone(),
            poster: poster.clone(),
            category: category.clone(),
            data: data.clone(),
            timestamp,
        };
        state
            .torrent_metadata
            .write()
            .await
            .insert(hash.clone(), metadata);
    }

    // Spawn torrent addition in background so it continues even if we return early
    let add_torrent = AddTorrent::Url(std::borrow::Cow::Owned(link.clone()));
    let add_opts = Some(AddTorrentOptions {
        overwrite: true, // Allow overwriting existing files
        ..Default::default()
    });
    let session = state.session.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();

    // Log torrent addition with tracker info
    let trackers = extract_trackers(&link);
    println!("[ADD] Adding torrent: hash={}", hash);
    if !trackers.is_empty() {
        println!("[ADD] Trackers ({}):", trackers.len());
        for tracker in &trackers {
            println!("[ADD]   {}", tracker);
        }
    }

    let hash_for_log = hash.clone();
    tokio::spawn(async move {
        println!("[DHT] Starting DHT lookup for hash={}", hash_for_log);
        let start = std::time::Instant::now();
        let result = session.add_torrent(add_torrent, add_opts).await;
        let elapsed = start.elapsed();
        match &result {
            Ok(librqbit::AddTorrentResponse::Added(id, handle)) => {
                println!(
                    "[DHT] Torrent metadata resolved: hash={}, id={}, name={:?}, took {:?}",
                    hash_for_log,
                    id,
                    handle.name(),
                    elapsed
                );
                // Spawn background task to monitor hashing progress
                let handle_clone = handle.clone();
                let hash_for_monitor = hash_for_log.clone();
                tokio::spawn(async move {
                    monitor_hashing_progress(handle_clone, hash_for_monitor).await;
                });
            }
            Ok(librqbit::AddTorrentResponse::AlreadyManaged(id, handle)) => {
                println!(
                    "[DHT] Torrent already managed: hash={}, id={}, name={:?}, took {:?}",
                    hash_for_log,
                    id,
                    handle.name(),
                    elapsed
                );
            }
            Ok(librqbit::AddTorrentResponse::ListOnly(_)) => {
                println!(
                    "[DHT] List only response: hash={}, took {:?}",
                    hash_for_log, elapsed
                );
            }
            Err(e) => {
                eprintln!(
                    "[DHT] Error adding torrent: hash={}, error={}",
                    hash_for_log, e
                );
            }
        }
        let _ = tx.send(result);
    });

    // Wait with timeout for the result
    match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(Ok(Ok(response))) => {
            if let Some(handle) = response.into_handle() {
                let hash = handle.info_hash().as_string();
                let stats = handle.stats();
                let (name, file_stats, torrent_size) = get_torrent_info(&handle);

                let status = TorrentStatus {
                    title: title.clone(),
                    category: category.clone(),
                    poster: poster.clone(),
                    data: data.clone(),
                    timestamp,
                    name,
                    hash,
                    stat: TorrentStat::TorrentWorking as i32,
                    stat_string: "Torrent working".to_string(),
                    torrent_size,
                    download_speed: stats
                        .live
                        .as_ref()
                        .map(|l| l.download_speed.mbps * 125000.0)
                        .unwrap_or(0.0),
                    upload_speed: stats
                        .live
                        .as_ref()
                        .map(|l| l.upload_speed.mbps * 125000.0)
                        .unwrap_or(0.0),
                    total_peers: stats
                        .live
                        .as_ref()
                        .map(|l| l.snapshot.peer_stats.live as i32)
                        .unwrap_or(0),
                    active_peers: stats
                        .live
                        .as_ref()
                        .map(|l| l.snapshot.peer_stats.live as i32)
                        .unwrap_or(0),
                    file_stats,
                    ..Default::default()
                };
                return Ok(Json(status).into_response());
            }
        }
        Ok(Ok(Err(e))) => {
            eprintln!(
                "[DHT] Add torrent failed immediately: hash={}, error={}",
                hash, e
            );
            return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
        }
        Ok(Err(_)) => {
            // Channel closed - shouldn't happen
            println!("[DHT] Channel closed unexpectedly: hash={}", hash);
        }
        Err(_) => {
            // Timeout - torrent is being added in background, metadata not ready yet
            // This is expected for magnet links
            println!(
                "[DHT] Timeout waiting for metadata (5s), DHT lookup continues in background: hash={}",
                hash
            );
        }
    }

    // Return status indicating torrent is being fetched (addition continues in background)
    let status = TorrentStatus {
        title: title.clone(),
        category,
        poster,
        data,
        timestamp,
        name: format!("infohash:{}", hash),
        hash,
        stat: TorrentStat::TorrentGettingInfo as i32,
        stat_string: "Torrent getting info".to_string(),
        ..Default::default()
    };

    Ok(Json(status).into_response())
}

async fn torrents_get(
    state: Arc<AppState>,
    req: TorrentsRequest,
) -> Result<Response, (StatusCode, String)> {
    let hash = req.hash.ok_or((
        StatusCode::BAD_REQUEST,
        "hash is required for get action".to_string(),
    ))?;

    let hash_lower = hash.to_lowercase();

    // Get stored metadata
    let metadata = state
        .torrent_metadata
        .read()
        .await
        .get(&hash_lower)
        .cloned()
        .unwrap_or_default();

    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Try to get the torrent handle
    match state.api.mgr_handle(id) {
        Ok(handle) => {
            let stats = handle.stats();
            let hash_str = handle.info_hash().as_string();
            let (name, file_stats, torrent_size) = get_torrent_info(&handle);

            let status = TorrentStatus {
                title: metadata.title,
                category: metadata.category,
                poster: metadata.poster,
                data: metadata.data,
                timestamp: metadata.timestamp,
                name,
                hash: hash_str,
                stat: TorrentStat::TorrentWorking as i32,
                stat_string: "Torrent working".to_string(),
                torrent_size,
                download_speed: stats
                    .live
                    .as_ref()
                    .map(|l| l.download_speed.mbps * 125000.0)
                    .unwrap_or(0.0),
                upload_speed: stats
                    .live
                    .as_ref()
                    .map(|l| l.upload_speed.mbps * 125000.0)
                    .unwrap_or(0.0),
                total_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.live as i32)
                    .unwrap_or(0),
                active_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.live as i32)
                    .unwrap_or(0),
                file_stats,
                ..Default::default()
            };

            Ok(Json(status).into_response())
        }
        Err(_) => {
            // Torrent not found - might still be resolving metadata
            // Return "getting info" status instead of error (TorrServer compatibility)
            let status = TorrentStatus {
                title: metadata.title,
                category: metadata.category,
                poster: metadata.poster,
                data: metadata.data,
                timestamp: metadata.timestamp,
                name: format!("infohash:{}", hash_lower),
                hash: hash_lower,
                stat: TorrentStat::TorrentGettingInfo as i32,
                stat_string: "Torrent getting info".to_string(),
                ..Default::default()
            };

            Ok(Json(status).into_response())
        }
    }
}

async fn torrents_set(
    state: Arc<AppState>,
    req: TorrentsRequest,
) -> Result<Response, (StatusCode, String)> {
    let hash = req.hash.ok_or((
        StatusCode::BAD_REQUEST,
        "hash is required for set action".to_string(),
    ))?;

    let hash_lower = hash.to_lowercase();

    // Update metadata in store
    {
        let mut store = state.torrent_metadata.write().await;
        if let Some(metadata) = store.get_mut(&hash_lower) {
            if let Some(title) = req.title {
                metadata.title = title;
            }
            if let Some(poster) = req.poster {
                metadata.poster = poster;
            }
            if let Some(category) = req.category {
                metadata.category = category;
            }
            if let Some(data) = req.data {
                metadata.data = data;
            }
        } else {
            // Create new metadata entry if doesn't exist
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            store.insert(
                hash_lower,
                TorrentMetadata {
                    title: req.title.unwrap_or_default(),
                    poster: req.poster.unwrap_or_default(),
                    category: req.category.unwrap_or_default(),
                    data: req.data.unwrap_or_default(),
                    timestamp,
                },
            );
        }
    }

    // TorrServer returns just HTTP 200 with no body
    Ok(StatusCode::OK.into_response())
}

async fn torrents_remove(
    state: Arc<AppState>,
    req: TorrentsRequest,
) -> Result<Response, (StatusCode, String)> {
    let hash = req.hash.ok_or((
        StatusCode::BAD_REQUEST,
        "hash is required for rem/drop action".to_string(),
    ))?;

    let hash_lower = hash.to_lowercase();

    // Always remove from metadata store
    state.torrent_metadata.write().await.remove(&hash_lower);

    // Try to delete from session (may fail if torrent is still resolving)
    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Ignore errors - torrent might not be in session yet
    let _ = state.session.delete(id, false).await;

    // TorrServer returns just HTTP 200 with no body
    Ok(StatusCode::OK.into_response())
}

async fn torrents_list(state: Arc<AppState>) -> Result<Response, (StatusCode, String)> {
    let list = state.api.api_torrent_list();
    let metadata_store = state.torrent_metadata.read().await;

    // Get hashes of torrents already in librqbit session
    let session_hashes: std::collections::HashSet<String> = list
        .torrents
        .iter()
        .map(|t| t.info_hash.to_lowercase())
        .collect();

    // Build list from session torrents with metadata and stats
    let mut torrents: Vec<TorrentStatus> = Vec::new();
    for t in &list.torrents {
        let hash_lower = t.info_hash.to_lowercase();
        let metadata = metadata_store.get(&hash_lower).cloned().unwrap_or_default();

        // Get torrent handle for statistics
        let (torrent_size, download_speed, upload_speed, total_peers, active_peers, file_stats) =
            if let Some(id) = t.id {
                if let Ok(handle) = state.api.mgr_handle(TorrentIdOrHash::Id(id)) {
                    let stats = handle.stats();
                    let (_, files, size) = get_torrent_info(&handle);
                    (
                        size,
                        stats
                            .live
                            .as_ref()
                            .map(|l| l.download_speed.mbps * 125000.0)
                            .unwrap_or(0.0),
                        stats
                            .live
                            .as_ref()
                            .map(|l| l.upload_speed.mbps * 125000.0)
                            .unwrap_or(0.0),
                        stats
                            .live
                            .as_ref()
                            .map(|l| l.snapshot.peer_stats.live as i32)
                            .unwrap_or(0),
                        stats
                            .live
                            .as_ref()
                            .map(|l| l.snapshot.peer_stats.live as i32)
                            .unwrap_or(0),
                        files,
                    )
                } else {
                    (0, 0.0, 0.0, 0, 0, vec![])
                }
            } else {
                (0, 0.0, 0.0, 0, 0, vec![])
            };

        torrents.push(TorrentStatus {
            title: metadata.title,
            category: metadata.category,
            poster: metadata.poster,
            data: metadata.data,
            timestamp: metadata.timestamp,
            name: t.name.clone().unwrap_or_default(),
            hash: t.info_hash.clone(),
            stat: TorrentStat::TorrentWorking as i32,
            stat_string: "Torrent working".to_string(),
            torrent_size,
            download_speed,
            upload_speed,
            total_peers,
            active_peers,
            file_stats,
            ..Default::default()
        });
    }

    // Add torrents that are in metadata store but not yet in session (still resolving)
    for (hash, metadata) in metadata_store.iter() {
        if !session_hashes.contains(hash) {
            torrents.push(TorrentStatus {
                title: metadata.title.clone(),
                category: metadata.category.clone(),
                poster: metadata.poster.clone(),
                data: metadata.data.clone(),
                timestamp: metadata.timestamp,
                name: format!("infohash:{}", hash),
                hash: hash.clone(),
                stat: TorrentStat::TorrentGettingInfo as i32,
                stat_string: "Torrent getting info".to_string(),
                ..Default::default()
            });
        }
    }

    Ok(Json(torrents).into_response())
}

async fn torrents_wipe(state: Arc<AppState>) -> Result<Response, (StatusCode, String)> {
    let list = state.api.api_torrent_list();

    // Delete each torrent from session
    for t in list.torrents {
        if let Some(id) = t.id {
            let _ = state.session.delete(TorrentIdOrHash::Id(id), true).await;
        }
    }

    // Clear metadata store
    state.torrent_metadata.write().await.clear();

    // TorrServer returns just HTTP 200 with no body
    Ok(StatusCode::OK.into_response())
}

// ============================================================================
// GET /stream/*path - Stream torrent content
// ============================================================================
pub async fn stream_handler(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(params): Query<StreamQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    // If stat param is present, return torrent status
    if params.stat.is_some() {
        return stream_stat(&state, &params).await;
    }

    // If m3u param is present, return M3U playlist
    if params.m3u.is_some() {
        return stream_m3u(&state, &params, &path).await;
    }

    // Otherwise, proxy to rqbit stream
    stream_content(&state, &params, &path, headers).await
}

async fn stream_stat(
    state: &Arc<AppState>,
    params: &StreamQuery,
) -> Result<Response, (StatusCode, String)> {
    let hash = extract_hash(&params.link);
    let hash_lower = hash.to_lowercase();

    // Get stored metadata
    let metadata = state
        .torrent_metadata
        .read()
        .await
        .get(&hash_lower)
        .cloned()
        .unwrap_or_default();

    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Try to get the torrent handle
    match state.api.mgr_handle(id) {
        Ok(handle) => {
            let stats = handle.stats();
            let (name, file_stats, torrent_size) = get_torrent_info(&handle);

            let status = TorrentStatus {
                title: metadata.title,
                category: metadata.category,
                poster: metadata.poster,
                data: metadata.data,
                timestamp: metadata.timestamp,
                hash: hash_lower,
                name,
                stat: TorrentStat::TorrentWorking as i32,
                stat_string: "Torrent working".to_string(),
                torrent_size,
                loaded_size: stats.progress_bytes as i64,
                preloaded_bytes: stats.progress_bytes as i64,
                preload_size: (torrent_size as f64 * 0.05) as i64, // 5% preload
                download_speed: stats
                    .live
                    .as_ref()
                    .map(|l| l.download_speed.mbps * 125000.0)
                    .unwrap_or(0.0),
                upload_speed: stats
                    .live
                    .as_ref()
                    .map(|l| l.upload_speed.mbps * 125000.0)
                    .unwrap_or(0.0),
                total_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.live as i32)
                    .unwrap_or(0),
                active_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.live as i32)
                    .unwrap_or(0),
                pending_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.connecting as i32)
                    .unwrap_or(0),
                half_open_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.connecting as i32)
                    .unwrap_or(0),
                connected_seeders: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.seen as i32)
                    .unwrap_or(0),
                bytes_read: stats.progress_bytes as i64,
                bytes_read_data: stats.progress_bytes as i64,
                bytes_read_useful_data: stats.progress_bytes as i64,
                bytes_written: stats.uploaded_bytes as i64,
                chunks_read: (stats.progress_bytes / 16384) as i64,
                chunks_read_useful: (stats.progress_bytes / 16384) as i64,
                chunks_read_wasted: 0,
                pieces_dirtied_good: calculate_completed_pieces(&handle),
                file_stats,
                ..Default::default()
            };

            Ok(Json(status).into_response())
        }
        Err(_) => {
            // Torrent not found in session - might still be resolving
            // Return "getting info" status (TorrServer compatibility)
            let status = TorrentStatus {
                title: metadata.title,
                category: metadata.category,
                poster: metadata.poster,
                data: metadata.data,
                timestamp: metadata.timestamp,
                name: format!("infohash:{}", hash_lower),
                hash: hash_lower,
                stat: TorrentStat::TorrentGettingInfo as i32,
                stat_string: "Torrent getting info".to_string(),
                ..Default::default()
            };

            Ok(Json(status).into_response())
        }
    }
}

async fn stream_m3u(
    state: &Arc<AppState>,
    params: &StreamQuery,
    _path: &str,
) -> Result<Response, (StatusCode, String)> {
    let hash = extract_hash(&params.link);

    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let handle = state
        .api
        .mgr_handle(id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let meta = handle.metadata.load();
    let meta = meta.as_ref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Torrent metadata not available".to_string(),
    ))?;

    let mut m3u = String::from("#EXTM3U\n");
    if let Ok(files) = meta.info.iter_file_details() {
        for (idx, file) in files.enumerate() {
            if let Ok(filename) = file.filename.to_string() {
                // Only include video/audio files
                if is_media_file(&filename) {
                    m3u.push_str(&format!(
                        "#EXTINF:-1,{}\n/stream/{}?link={}&index={}&play=1\n",
                        filename, filename, hash, idx
                    ));
                }
            }
        }
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "audio/x-mpegurl")
        .body(Body::from(m3u))
        .unwrap())
}

async fn stream_content(
    state: &Arc<AppState>,
    params: &StreamQuery,
    _path: &str,
    headers: axum::http::HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let hash = extract_hash(&params.link);
    let hash_lower = hash.to_lowercase();
    let index = params.index.unwrap_or(0);

    // Get stored metadata
    let metadata = state
        .torrent_metadata
        .read()
        .await
        .get(&hash_lower)
        .cloned()
        .unwrap_or_default();

    // First, try to find the torrent
    let torrent_id = match find_torrent_id_by_hash(&state, &hash) {
        Ok(id) => id,
        Err(_) => {
            // Try to add it as a magnet link
            let magnet = if params.link.starts_with("magnet:") {
                params.link.clone()
            } else {
                format!("magnet:?xt=urn:btih:{}", hash)
            };

            let add_torrent = AddTorrent::from_url(&magnet);
            let add_opts = Some(AddTorrentOptions {
                overwrite: true,
                ..Default::default()
            });
            let response = state
                .session
                .add_torrent(add_torrent, add_opts)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let handle = response.into_handle().ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get torrent handle".to_string(),
            ))?;

            handle.id()
        }
    };

    // Get torrent handle to check preload status
    let id = TorrentIdOrHash::Id(torrent_id);
    if let Ok(handle) = state.api.mgr_handle(id) {
        let stats = handle.stats();
        let (name, file_stats, torrent_size) = get_torrent_info(&handle);

        // Calculate preload threshold (5% of file)
        let preload_size = (torrent_size as f64 * 0.05) as u64;

        // If we haven't downloaded enough for preload, return preload status
        if stats.progress_bytes < preload_size {
            let status = TorrentStatus {
                title: metadata.title,
                category: metadata.category,
                poster: metadata.poster,
                data: metadata.data,
                timestamp: metadata.timestamp,
                hash: hash_lower,
                name,
                stat: TorrentStat::TorrentPreload as i32,
                stat_string: "Torrent preload".to_string(),
                torrent_size,
                loaded_size: stats.progress_bytes as i64,
                preloaded_bytes: stats.progress_bytes as i64,
                preload_size: preload_size as i64,
                download_speed: stats
                    .live
                    .as_ref()
                    .map(|l| l.download_speed.mbps * 125000.0)
                    .unwrap_or(0.0),
                upload_speed: stats
                    .live
                    .as_ref()
                    .map(|l| l.upload_speed.mbps * 125000.0)
                    .unwrap_or(0.0),
                total_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.live as i32)
                    .unwrap_or(0),
                active_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.live as i32)
                    .unwrap_or(0),
                pending_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.connecting as i32)
                    .unwrap_or(0),
                half_open_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.connecting as i32)
                    .unwrap_or(0),
                connected_seeders: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.seen as i32)
                    .unwrap_or(0),
                bytes_read: stats.progress_bytes as i64,
                bytes_read_data: stats.progress_bytes as i64,
                bytes_read_useful_data: stats.progress_bytes as i64,
                bytes_written: stats.uploaded_bytes as i64,
                chunks_read: (stats.progress_bytes / 16384) as i64,
                chunks_read_useful: (stats.progress_bytes / 16384) as i64,
                chunks_read_wasted: 0,
                pieces_dirtied_good: calculate_completed_pieces(&handle),
                file_stats,
                ..Default::default()
            };

            return Ok(Json(status).into_response());
        }
    }

    // Preload complete - stream directly from librqbit
    // Convert from 1-based index (TorrServer) to 0-based index (rqbit)
    let rqbit_index = if index > 0 { index - 1 } else { 0 };

    // Get file stream directly from librqbit
    let mut file_stream = state
        .api
        .api_stream(TorrentIdOrHash::Id(torrent_id), rqbit_index)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Trigger sequential loading from the beginning by reading a small chunk
    // This ensures the torrent starts downloading from the first pieces
    let mut preload_buf = vec![0u8; 4096];
    let _ = file_stream.read(&mut preload_buf).await;

    // Reset to beginning for actual streaming
    use tokio::io::AsyncSeekExt;
    let _ = file_stream.seek(std::io::SeekFrom::Start(0)).await;

    // Get file info for content type and size
    let handle = state
        .api
        .mgr_handle(TorrentIdOrHash::Id(torrent_id))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (filename, file_length) = if let Some(meta) = &*handle.metadata.load() {
        if let Ok(mut files) = meta.info.iter_file_details() {
            if let Some(f) = files.nth(rqbit_index) {
                (
                    f.filename
                        .to_string()
                        .ok()
                        .unwrap_or_else(|| "video.mkv".to_string()),
                    f.len,
                )
            } else {
                ("video.mkv".to_string(), 0)
            }
        } else {
            ("video.mkv".to_string(), 0)
        }
    } else {
        ("video.mkv".to_string(), 0)
    };

    // Determine content type from filename
    let content_type = mime_guess::from_path(&filename)
        .first_or_octet_stream()
        .to_string();

    // Check for Range header
    let range_header = headers.get(header::RANGE).and_then(|h| h.to_str().ok());

    if let Some((start, end)) = parse_range_header(range_header, file_length) {
        // Seek to the requested position
        use tokio::io::AsyncSeekExt;
        file_stream
            .seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let content_length = end - start + 1;
        let content_range = format!("bytes {}-{}/{}", start, end, file_length);

        // Return 206 Partial Content
        Ok(Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, content_length.to_string())
            .header(header::CONTENT_RANGE, content_range)
            .header("Accept-Ranges", "bytes")
            .body(Body::from_stream(ReaderStream::new(file_stream)))
            .unwrap())
    } else {
        // Stream the full file
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, file_length.to_string())
            .header("Accept-Ranges", "bytes")
            .body(Body::from_stream(ReaderStream::new(file_stream)))
            .unwrap())
    }
}

// ============================================================================
// GET /play/{hash}/{id} - Play specific file from torrent
// ============================================================================
pub async fn play_handler(
    State(state): State<Arc<AppState>>,
    Path((hash, file_id)): Path<(String, usize)>,
    headers: axum::http::HeaderMap,
) -> Result<Response, (StatusCode, String)> {
    let torrent_id = find_torrent_id_by_hash(&state, &hash)?;

    // Stream directly from librqbit
    // Convert from 1-based index (TorrServer) to 0-based index (rqbit)
    let rqbit_index = if file_id > 0 { file_id - 1 } else { 0 };

    // Get file stream directly from librqbit
    let mut file_stream = state
        .api
        .api_stream(TorrentIdOrHash::Id(torrent_id), rqbit_index)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Trigger sequential loading from the beginning by reading a small chunk
    // This ensures the torrent starts downloading from the first pieces
    let mut preload_buf = vec![0u8; 4096];
    let _ = file_stream.read(&mut preload_buf).await;

    // Reset to beginning for actual streaming
    use tokio::io::AsyncSeekExt;
    let _ = file_stream.seek(std::io::SeekFrom::Start(0)).await;

    // Get file info for content type and size
    let handle = state
        .api
        .mgr_handle(TorrentIdOrHash::Id(torrent_id))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (filename, file_length) = if let Some(meta) = &*handle.metadata.load() {
        if let Ok(mut files) = meta.info.iter_file_details() {
            if let Some(f) = files.nth(rqbit_index) {
                (
                    f.filename
                        .to_string()
                        .ok()
                        .unwrap_or_else(|| "video.mkv".to_string()),
                    f.len,
                )
            } else {
                ("video.mkv".to_string(), 0)
            }
        } else {
            ("video.mkv".to_string(), 0)
        }
    } else {
        ("video.mkv".to_string(), 0)
    };

    // Determine content type from filename
    let content_type = mime_guess::from_path(&filename)
        .first_or_octet_stream()
        .to_string();

    // Check for Range header
    let range_header = headers.get(header::RANGE).and_then(|h| h.to_str().ok());

    if let Some((start, end)) = parse_range_header(range_header, file_length) {
        // Seek to the requested position
        use tokio::io::AsyncSeekExt;
        file_stream
            .seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let content_length = end - start + 1;
        let content_range = format!("bytes {}-{}/{}", start, end, file_length);

        // Return 206 Partial Content
        Ok(Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, content_length.to_string())
            .header(header::CONTENT_RANGE, content_range)
            .header("Accept-Ranges", "bytes")
            .body(Body::from_stream(ReaderStream::new(file_stream)))
            .unwrap())
    } else {
        // Stream the full file
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type)
            .header(header::CONTENT_LENGTH, file_length.to_string())
            .header("Accept-Ranges", "bytes")
            .body(Body::from_stream(ReaderStream::new(file_stream)))
            .unwrap())
    }
}

// ============================================================================
// POST /settings - Get/set server settings
// ============================================================================
pub async fn settings_handler(
    State(_state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let req: SettingsRequest = parse_json(&body)?;
    match req.action.as_str() {
        "get" => {
            // Return current settings (defaults for now)
            let settings = BTSets::default();
            Ok(Json(settings).into_response())
        }
        "set" => {
            // Accept settings but rqbit doesn't support runtime config changes
            Ok(Json(serde_json::json!({"status": "ok"})).into_response())
        }
        "def" => {
            // Return default settings
            let settings = BTSets::default();
            Ok(Json(settings).into_response())
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("Unknown action: {}", req.action),
        )),
    }
}

// ============================================================================
// GET /shutdown - Gracefully shutdown server
// ============================================================================
pub async fn shutdown_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Signal shutdown
    if let Some(tx) = state.shutdown_tx.lock().await.take() {
        let _ = tx.send(());
    }
    "OK"
}

// ============================================================================
// POST /viewed - Handle viewed items
// ============================================================================
pub async fn viewed_handler(
    State(_state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let req: ViewedRequest = parse_json(&body)?;
    match req.action.as_str() {
        "list" => {
            // Return empty list (rqbit doesn't track viewed state)
            let viewed: Vec<Viewed> = vec![];
            Ok(Json(viewed).into_response())
        }
        "set" | "rem" => {
            // Accept but don't persist (rqbit doesn't support this)
            Ok(Json(serde_json::json!({"status": "ok"})).into_response())
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("Unknown action: {}", req.action),
        )),
    }
}

// ============================================================================
// POST /cache - Return cache stats
// ============================================================================
pub async fn cache_handler(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, (StatusCode, String)> {
    let req: CacheRequest = parse_json(&body)?;
    let hash = req
        .hash
        .ok_or((StatusCode::BAD_REQUEST, "hash is required".to_string()))?;

    let hash_lower = hash.to_lowercase();

    // Get stored metadata
    let metadata = state
        .torrent_metadata
        .read()
        .await
        .get(&hash_lower)
        .cloned()
        .unwrap_or_default();

    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Try to get the torrent handle
    match state.api.mgr_handle(id) {
        Ok(handle) => {
            let stats = handle.stats();
            let (name, file_stats, torrent_size) = get_torrent_info(&handle);

            // Get real piece availability from chunk tracker
            let (pieces_count, pieces_length, pieces, completed_pieces_count) = if let Some(meta) =
                &*handle.metadata.load()
            {
                let piece_length = meta.lengths.default_piece_length() as u64;
                let num_pieces = meta.lengths.total_pieces() as i32;

                // Calculate piece availability based on file progress
                // Use per-file progress to determine which pieces have been downloaded
                let mut piece_availability = vec![false; num_pieces as usize];

                if let Ok(files) = meta.info.iter_file_details() {
                    let mut torrent_offset = 0u64;

                    for (file_idx, file) in files.enumerate() {
                        let file_progress = stats.file_progress.get(file_idx).copied().unwrap_or(0);

                        if file_progress > 0 {
                            // Calculate which pieces overlap with this file's downloaded bytes
                            let file_start = torrent_offset;
                            let file_downloaded_end = file_start + file_progress;

                            // Find first and last piece that contain downloaded data
                            let first_piece = (file_start / piece_length) as usize;
                            let last_piece =
                                ((file_downloaded_end.saturating_sub(1)) / piece_length) as usize;

                            // Mark all complete pieces as available
                            for piece_idx in first_piece..=last_piece.min(num_pieces as usize - 1) {
                                let piece_start = piece_idx as u64 * piece_length;
                                let piece_end = ((piece_idx + 1) as u64 * piece_length)
                                    .min(meta.lengths.total_length());

                                // A piece is complete if all its bytes are within downloaded range
                                if piece_start >= file_start && piece_end <= file_downloaded_end {
                                    piece_availability[piece_idx] = true;
                                }
                                // Also mark complete if we've downloaded enough bytes to cover this piece
                                else if file_downloaded_end >= piece_end {
                                    piece_availability[piece_idx] = true;
                                }
                            }
                        }

                        torrent_offset += file.len;
                    }
                }

                // Build pieces map with completion and partial download info
                // Calculate downloaded bytes per piece to show partial completion
                let mut piece_downloaded_bytes: Vec<u64> = vec![0; num_pieces as usize];

                if let Ok(files) = meta.info.iter_file_details() {
                    let mut torrent_offset = 0u64;

                    for (file_idx, file) in files.enumerate() {
                        let file_progress = stats.file_progress.get(file_idx).copied().unwrap_or(0);

                        if file_progress > 0 {
                            let file_start = torrent_offset;
                            let file_downloaded_end = file_start + file_progress;

                            // Calculate downloaded bytes for each piece this file overlaps
                            let first_piece = (file_start / piece_length) as usize;
                            let last_piece =
                                ((file_downloaded_end.saturating_sub(1)) / piece_length) as usize;

                            for piece_idx in first_piece..=last_piece.min(num_pieces as usize - 1) {
                                let piece_start = piece_idx as u64 * piece_length;
                                let piece_end = ((piece_idx + 1) as u64 * piece_length)
                                    .min(meta.lengths.total_length());

                                // Calculate overlap between downloaded range and this piece
                                let overlap_start = piece_start.max(file_start);
                                let overlap_end = piece_end.min(file_downloaded_end);

                                if overlap_end > overlap_start {
                                    piece_downloaded_bytes[piece_idx] +=
                                        overlap_end - overlap_start;
                                }
                            }
                        }

                        torrent_offset += file.len;
                    }
                }

                // Build pieces map - include completed and partially completed pieces
                let mut pieces_map: std::collections::BTreeMap<String, PieceState> =
                    std::collections::BTreeMap::new();
                let mut completed_count = 0i64;

                for i in 0..num_pieces {
                    let actual_piece_length = if i == num_pieces - 1 {
                        let total_len = meta.lengths.total_length();
                        (total_len - (piece_length * (num_pieces - 1) as u64)) as i64
                    } else {
                        piece_length as i64
                    };

                    let downloaded =
                        piece_downloaded_bytes.get(i as usize).copied().unwrap_or(0) as i64;
                    let is_completed = downloaded >= actual_piece_length;

                    // Include piece if it has any downloaded data
                    if downloaded > 0 {
                        if is_completed {
                            completed_count += 1;
                        }

                        // Set priority based on piece state
                        // Priority scale: 0 (no priority), 1-10 (downloading/partial), 11+ (being streamed)
                        let priority = if is_completed {
                            0 // Completed pieces have no priority
                        } else {
                            // Partial pieces get higher priority
                            // Higher priority for pieces with more data (actively downloading)
                            let completion_pct =
                                (downloaded as f64 / actual_piece_length as f64 * 100.0) as i32;
                            if completion_pct > 50 {
                                10 // High priority - more than half downloaded
                            } else if completion_pct > 10 {
                                5 // Medium priority
                            } else {
                                1 // Low priority - just started
                            }
                        };

                        pieces_map.insert(
                            i.to_string(), // 0-based piece numbering
                            PieceState {
                                id: i,
                                length: actual_piece_length,
                                size: downloaded, // Actual downloaded bytes
                                completed: is_completed,
                                priority,
                            },
                        );
                    }
                }

                (num_pieces, piece_length as i64, pieces_map, completed_count)
            } else {
                (0, 0, std::collections::BTreeMap::new(), 0)
            };

            // Now build the status with real piece count
            let status = TorrentStatus {
                title: metadata.title,
                category: metadata.category,
                poster: metadata.poster,
                data: metadata.data,
                timestamp: metadata.timestamp,
                hash: hash_lower.clone(),
                name,
                stat: TorrentStat::TorrentWorking as i32,
                stat_string: "Torrent working".to_string(),
                torrent_size,
                loaded_size: stats.progress_bytes as i64,
                preloaded_bytes: stats.progress_bytes as i64,
                preload_size: (torrent_size as f64 * 0.05) as i64, // 5% preload
                download_speed: stats
                    .live
                    .as_ref()
                    .map(|l| l.download_speed.mbps * 125000.0)
                    .unwrap_or(0.0),
                upload_speed: stats
                    .live
                    .as_ref()
                    .map(|l| l.upload_speed.mbps * 125000.0)
                    .unwrap_or(0.0),
                total_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.live as i32)
                    .unwrap_or(0),
                active_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.live as i32)
                    .unwrap_or(0),
                pending_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.connecting as i32)
                    .unwrap_or(0),
                half_open_peers: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.connecting as i32)
                    .unwrap_or(0),
                connected_seeders: stats
                    .live
                    .as_ref()
                    .map(|l| l.snapshot.peer_stats.seen as i32)
                    .unwrap_or(0),
                bytes_read: stats.progress_bytes as i64,
                bytes_read_data: stats.progress_bytes as i64,
                bytes_read_useful_data: stats.progress_bytes as i64,
                bytes_written: stats.uploaded_bytes as i64,
                chunks_read: (stats.progress_bytes / 16384) as i64,
                chunks_read_useful: (stats.progress_bytes / 16384) as i64,
                chunks_read_wasted: 0,
                pieces_dirtied_good: completed_pieces_count, // Real completed pieces count
                file_stats,
                ..Default::default()
            };

            let cache_state = CacheState {
                hash: hash_lower,
                capacity: torrent_size,
                filled: stats.progress_bytes as i64,
                pieces_count,
                pieces_length,
                torrent: Some(status),
                pieces,
                readers: vec![],
            };

            Ok(Json(cache_state).into_response())
        }
        Err(_) => {
            // Torrent not found in session - might still be resolving
            // Return empty cache state with "getting info" status
            let status = TorrentStatus {
                title: metadata.title,
                category: metadata.category,
                poster: metadata.poster,
                data: metadata.data,
                timestamp: metadata.timestamp,
                name: format!("infohash:{}", hash_lower),
                hash: hash_lower.clone(),
                stat: TorrentStat::TorrentGettingInfo as i32,
                stat_string: "Torrent getting info".to_string(),
                ..Default::default()
            };

            let cache_state = CacheState {
                hash: hash_lower,
                capacity: 0,
                filled: 0,
                pieces_count: 0,
                pieces_length: 0,
                torrent: Some(status),
                pieces: std::collections::BTreeMap::new(), // Empty but defined
                readers: vec![],
            };

            Ok(Json(cache_state).into_response())
        }
    }
}

// ============================================================================
// GET /stat - Return server statistics
// ============================================================================
pub async fn stat_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let list = state.api.api_torrent_list();
    format!("Torrents: {}\nrqbit-torrserver bridge", list.torrents.len())
}

// ============================================================================
// GET /playlist - Return M3U playlist for torrent
// ============================================================================
pub async fn playlist_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PlaylistQuery>,
) -> Result<Response, (StatusCode, String)> {
    let id = TorrentIdOrHash::try_from(params.hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let handle = state
        .api
        .mgr_handle(id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let meta = handle.metadata.load();
    let meta = meta.as_ref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Torrent metadata not available".to_string(),
    ))?;

    let mut m3u = String::from("#EXTM3U\n");
    if let Ok(files) = meta.info.iter_file_details() {
        for (idx, file) in files.enumerate() {
            if let Ok(filename) = file.filename.to_string() {
                if is_media_file(&filename) {
                    m3u.push_str(&format!(
                        "#EXTINF:-1,{}\n/stream/{}?link={}&index={}&play=1\n",
                        filename, filename, params.hash, idx
                    ));
                }
            }
        }
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "audio/x-mpegurl")
        .body(Body::from(m3u))
        .unwrap())
}

// ============================================================================
// Helper functions
// ============================================================================

/// Calculate accurate completed piece count from file progress
fn calculate_completed_pieces(handle: &librqbit::ManagedTorrent) -> i64 {
    if let Some(meta) = &*handle.metadata.load() {
        let stats = handle.stats();
        let piece_length = meta.lengths.default_piece_length() as u64;
        let num_pieces = meta.lengths.total_pieces() as usize;

        let mut piece_availability = vec![false; num_pieces];

        if let Ok(files) = meta.info.iter_file_details() {
            let mut torrent_offset = 0u64;

            for (file_idx, file) in files.enumerate() {
                let file_progress = stats.file_progress.get(file_idx).copied().unwrap_or(0);

                if file_progress > 0 {
                    let file_start = torrent_offset;
                    let file_downloaded_end = file_start + file_progress;

                    let first_piece = (file_start / piece_length) as usize;
                    let last_piece =
                        ((file_downloaded_end.saturating_sub(1)) / piece_length) as usize;

                    for piece_idx in first_piece..=last_piece.min(num_pieces - 1) {
                        let piece_start = piece_idx as u64 * piece_length;
                        let piece_end = ((piece_idx + 1) as u64 * piece_length)
                            .min(meta.lengths.total_length());

                        if piece_start >= file_start && piece_end <= file_downloaded_end {
                            piece_availability[piece_idx] = true;
                        } else if file_downloaded_end >= piece_end {
                            piece_availability[piece_idx] = true;
                        }
                    }
                }

                torrent_offset += file.len;
            }
        }

        piece_availability.iter().filter(|&&x| x).count() as i64
    } else {
        0
    }
}

fn extract_hash(link: &str) -> String {
    if link.starts_with("magnet:") {
        // Extract hash from magnet link
        link.split("btih:")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .unwrap_or(link)
            .to_lowercase()
    } else {
        link.to_lowercase()
    }
}

fn extract_trackers(link: &str) -> Vec<String> {
    if !link.starts_with("magnet:") {
        return vec![];
    }

    // Parse trackers from magnet link (tr= parameters)
    link.split('&')
        .filter_map(|part| {
            let part = part.trim_start_matches("magnet:?");
            if part.starts_with("tr=") {
                // URL decode the tracker
                urlencoding::decode(&part[3..]).ok().map(|s| s.into_owned())
            } else {
                None
            }
        })
        .collect()
}

fn parse_range_header(range_header: Option<&str>, file_size: u64) -> Option<(u64, u64)> {
    range_header?;
    let range = range_header.unwrap();

    // Parse "bytes=start-end" format
    if !range.starts_with("bytes=") {
        return None;
    }

    let range = &range[6..]; // Skip "bytes="
    let parts: Vec<&str> = range.split('-').collect();

    if parts.len() != 2 {
        return None;
    }

    let start = parts[0].parse::<u64>().ok()?;
    let end = if parts[1].is_empty() {
        file_size - 1
    } else {
        parts[1].parse::<u64>().ok()?.min(file_size - 1)
    };

    if start <= end && start < file_size {
        Some((start, end))
    } else {
        None
    }
}

fn find_torrent_id_by_hash(
    state: &Arc<AppState>,
    hash: &str,
) -> Result<usize, (StatusCode, String)> {
    let hash_lower = hash.to_lowercase();
    let list = state.api.api_torrent_list();

    list.torrents
        .iter()
        .find(|t| t.info_hash.to_lowercase() == hash_lower)
        .and_then(|t| t.id)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("Torrent not found: {}", hash),
        ))
}

fn get_torrent_info(handle: &librqbit::ManagedTorrent) -> (String, Vec<TorrentFileStat>, i64) {
    if let Some(meta) = &*handle.metadata.load() {
        let name = meta.name.clone().unwrap_or_default();
        let size = meta.lengths.total_length() as i64;
        let files: Vec<TorrentFileStat> = if let Ok(file_iter) = meta.info.iter_file_details() {
            file_iter
                .enumerate()
                .filter_map(|(id, f)| {
                    f.filename.to_string().ok().map(|path| TorrentFileStat {
                        id: (id + 1) as i32, // TorrServer uses 1-based IDs (0 is undefined in web UI)
                        path,
                        length: f.len as i64,
                    })
                })
                .collect()
        } else {
            vec![]
        };
        (name, files, size)
    } else {
        (handle.name().unwrap_or_default(), vec![], 0)
    }
}

fn is_media_file(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    lower.ends_with(".mp4")
        || lower.ends_with(".mkv")
        || lower.ends_with(".avi")
        || lower.ends_with(".mov")
        || lower.ends_with(".wmv")
        || lower.ends_with(".flv")
        || lower.ends_with(".webm")
        || lower.ends_with(".m4v")
        || lower.ends_with(".mp3")
        || lower.ends_with(".flac")
        || lower.ends_with(".wav")
        || lower.ends_with(".aac")
        || lower.ends_with(".ogg")
        || lower.ends_with(".m4a")
}

/// Monitor hashing/initialization progress for a torrent and log to console
async fn monitor_hashing_progress(handle: std::sync::Arc<librqbit::ManagedTorrent>, hash: String) {
    let start = std::time::Instant::now();
    let mut last_state = String::new();
    let mut last_progress: u64 = 0;

    loop {
        let stats = handle.stats();
        let state = format!("{:?}", stats.state);
        let progress_bytes = stats.progress_bytes;
        let total_bytes = stats.total_bytes;

        // Calculate progress percentage
        let progress_pct = if total_bytes > 0 {
            (progress_bytes as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };

        // Log state changes
        if state != last_state {
            println!(
                "[HASH] State changed: hash={}, state={}, progress={:.1}% ({}/{})",
                hash,
                state,
                progress_pct,
                format_bytes(progress_bytes),
                format_bytes(total_bytes)
            );
            last_state = state.clone();
        }

        // Log progress updates during initialization (every 10% or significant change)
        if state == "Initializing" && progress_bytes > last_progress {
            let last_pct = if total_bytes > 0 {
                (last_progress as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };

            if progress_pct - last_pct >= 10.0 || progress_bytes - last_progress > 100_000_000 {
                println!(
                    "[HASH] Hashing progress: hash={}, {:.1}% ({}/{}), elapsed={:?}",
                    hash,
                    progress_pct,
                    format_bytes(progress_bytes),
                    format_bytes(total_bytes),
                    start.elapsed()
                );
                last_progress = progress_bytes;
            }
        }

        // Log peer info when live
        if let Some(live) = &stats.live {
            let peers = live.snapshot.peer_stats.live;
            let down_speed = live.download_speed.mbps;
            let up_speed = live.upload_speed.mbps;

            if peers > 0 || down_speed > 0.0 || up_speed > 0.0 {
                println!(
                    "[TORRENT] Status: hash={}, peers={}, down={:.2} MiB/s, up={:.2} MiB/s, progress={:.1}%",
                    hash, peers, down_speed, up_speed, progress_pct
                );
            }
        }

        // Stop monitoring when finished or after timeout
        if stats.finished {
            println!(
                "[HASH] Completed: hash={}, total={}, elapsed={:?}",
                hash,
                format_bytes(total_bytes),
                start.elapsed()
            );
            break;
        }

        // Stop monitoring after 5 minutes to avoid leaking tasks
        if start.elapsed() > std::time::Duration::from_secs(300) {
            println!(
                "[HASH] Monitoring timeout (5min): hash={}, state={}, progress={:.1}%",
                hash, state, progress_pct
            );
            break;
        }

        // Check every 2 seconds
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GiB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.2} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

// ============================================================================
// GET /announce - Retracker endpoint (fetch peers from opentor.org)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AnnounceQuery {
    pub info_hash: String,
    pub peer_id: String,
    #[serde(default)]
    pub event: Option<String>,
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    #[serde(default)]
    pub compact: Option<u8>,
    #[serde(default)]
    pub no_peer_id: Option<u8>,
}

pub async fn announce_handler(
    State(_state): State<Arc<AppState>>,
    Query(params): Query<AnnounceQuery>,
) -> Result<Response, (StatusCode, String)> {
    println!(
        "[RETRACKER] Announce request: info_hash={}",
        params.info_hash
    );

    // Parse info_hash (URL-encoded 20 bytes)
    let info_hash_bytes = urlencoding::decode_binary(params.info_hash.as_bytes());
    if info_hash_bytes.len() != 20 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid info_hash length: {} (expected 20)",
                info_hash_bytes.len()
            ),
        ));
    }
    let mut info_hash_array = [0u8; 20];
    info_hash_array.copy_from_slice(&info_hash_bytes);

    // Parse peer_id (URL-encoded 20 bytes)
    let peer_id_bytes = urlencoding::decode_binary(params.peer_id.as_bytes());
    if peer_id_bytes.len() != 20 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid peer_id length: {} (expected 20)",
                peer_id_bytes.len()
            ),
        ));
    }
    let mut peer_id_array = [0u8; 20];
    peer_id_array.copy_from_slice(&peer_id_bytes);

    // Convert event string to UDP tracker event code
    let event = match params.event.as_deref() {
        Some("started") | None => 2, // EVENT_STARTED
        Some("completed") => 1,      // EVENT_COMPLETED
        Some("stopped") => 3,        // EVENT_STOPPED
        _ => 0,                      // EVENT_NONE
    };

    // Define fallback trackers
    let trackers = [
        ("opentor.org:2710", "udp://opentor.org:2710"),
        (
            "tracker.opentrackr.org:1337",
            "udp://tracker.opentrackr.org:1337",
        ),
        ("open.stealth.si:80", "udp://open.stealth.si:80"),
    ];

    let mut all_peers = Vec::new();
    let mut successful_trackers = Vec::new();

    // Try each tracker in sequence
    for (host, tracker_url) in &trackers {
        println!("[RETRACKER] Trying tracker: {}", tracker_url);

        // Resolve tracker hostname to IP address
        let tracker_addr = match tokio::net::lookup_host(host).await {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => {
                    println!("[RETRACKER] Resolved {} to {}", host, addr);
                    addr
                }
                None => {
                    println!("[RETRACKER] DNS lookup returned no addresses for {}", host);
                    continue; // Try next tracker
                }
            },
            Err(e) => {
                println!("[RETRACKER] DNS lookup failed for {}: {}", host, e);
                continue; // Try next tracker
            }
        };

        // Make UDP tracker announce request
        let result = crate::udp_tracker::announce_to_udp_tracker(
            tracker_addr,
            info_hash_array,
            peer_id_array,
            params.port,
            params.uploaded,
            params.downloaded,
            params.left,
            event,
        )
        .await;

        match result {
            Ok(peers) => {
                if !peers.is_empty() {
                    println!(
                        "[RETRACKER] Received {} peers from {}",
                        peers.len(),
                        tracker_url
                    );
                    for peer_addr in &peers {
                        println!("[RETRACKER]   Peer: {}", peer_addr);
                    }

                    // Add unique peers to the collection
                    for peer in peers {
                        if !all_peers.contains(&peer) {
                            all_peers.push(peer);
                        }
                    }

                    successful_trackers.push(tracker_url);

                    // If we got peers, we can stop trying other trackers
                    // (remove this break if you want to query all trackers)
                    break;
                } else {
                    println!("[RETRACKER] No peers returned from {}", tracker_url);
                }
            }
            Err(e) => {
                println!("[RETRACKER] Tracker {} failed: {}", tracker_url, e);
                continue; // Try next tracker
            }
        }
    }

    // Check if we got any peers
    if all_peers.is_empty() {
        println!("[RETRACKER] No peers found from any tracker");
        return Err((
            StatusCode::NOT_FOUND,
            "No peers found from any tracker".to_string(),
        ));
    }

    println!(
        "[RETRACKER] Total unique peers: {} from {} tracker(s)",
        all_peers.len(),
        successful_trackers.len()
    );

    // Build a bencode response with peer list
    let mut response_text = format!("d8:intervali1800e5:peers{}:", all_peers.len() * 6);
    let mut peers_bytes = Vec::new();
    for peer_addr in &all_peers {
        if let std::net::IpAddr::V4(ipv4) = peer_addr.ip() {
            peers_bytes.extend_from_slice(&ipv4.octets());
            peers_bytes.extend_from_slice(&peer_addr.port().to_be_bytes());
        }
    }
    response_text.push_str(&String::from_utf8_lossy(&peers_bytes));
    response_text.push('e');

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(response_text))
        .unwrap())
}
