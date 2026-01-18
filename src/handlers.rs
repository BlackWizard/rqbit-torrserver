use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use librqbit::{AddTorrent, api::TorrentIdOrHash};
use std::sync::Arc;

use crate::models::*;
use crate::AppState;

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
    Json(req): Json<TorrentsRequest>,
) -> Result<Response, (StatusCode, String)> {
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

    let add_torrent = AddTorrent::from_url(&link);
    let response = state
        .session
        .add_torrent(add_torrent, None)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let handle = response.into_handle().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to get torrent handle".to_string(),
    ))?;

    let hash = handle.info_hash().as_string();
    let stats = handle.stats();
    let (name, file_stats, torrent_size) = get_torrent_info(&handle);

    let status = TorrentStatus {
        hash,
        name,
        title: req.title.unwrap_or_default(),
        poster: req.poster.unwrap_or_default(),
        category: req.category.unwrap_or_default(),
        stat: TorrentStat::TorrentWorking as i32,
        stat_string: "Torrent working".to_string(),
        torrent_size,
        download_speed: stats.live.as_ref().map(|l| l.download_speed.mbps * 125000.0).unwrap_or(0.0),
        upload_speed: stats.live.as_ref().map(|l| l.upload_speed.mbps * 125000.0).unwrap_or(0.0),
        total_peers: stats.live.as_ref().map(|l| l.snapshot.peer_stats.live as i32).unwrap_or(0),
        active_peers: stats.live.as_ref().map(|l| l.snapshot.peer_stats.live as i32).unwrap_or(0),
        file_stats,
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

    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let handle = state.api.mgr_handle(id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let stats = handle.stats();
    let hash_str = handle.info_hash().as_string();
    let (name, file_stats, torrent_size) = get_torrent_info(&handle);

    let status = TorrentStatus {
        hash: hash_str,
        name,
        stat: TorrentStat::TorrentWorking as i32,
        stat_string: "Torrent working".to_string(),
        torrent_size,
        download_speed: stats.live.as_ref().map(|l| l.download_speed.mbps * 125000.0).unwrap_or(0.0),
        upload_speed: stats.live.as_ref().map(|l| l.upload_speed.mbps * 125000.0).unwrap_or(0.0),
        total_peers: stats.live.as_ref().map(|l| l.snapshot.peer_stats.live as i32).unwrap_or(0),
        active_peers: stats.live.as_ref().map(|l| l.snapshot.peer_stats.live as i32).unwrap_or(0),
        file_stats,
        ..Default::default()
    };

    Ok(Json(status).into_response())
}

async fn torrents_set(
    state: Arc<AppState>,
    req: TorrentsRequest,
) -> Result<Response, (StatusCode, String)> {
    let hash = req.hash.ok_or((
        StatusCode::BAD_REQUEST,
        "hash is required for set action".to_string(),
    ))?;

    // Verify torrent exists
    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let _ = state.api.mgr_handle(id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    // In TorrServer, set updates metadata like title/poster/category
    // rqbit doesn't have this concept, so we just acknowledge
    Ok(Json(serde_json::json!({"status": "ok"})).into_response())
}

async fn torrents_remove(
    state: Arc<AppState>,
    req: TorrentsRequest,
) -> Result<Response, (StatusCode, String)> {
    let hash = req.hash.ok_or((
        StatusCode::BAD_REQUEST,
        "hash is required for rem/drop action".to_string(),
    ))?;

    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    state
        .session
        .delete(id, false)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({"status": "ok"})).into_response())
}

async fn torrents_list(state: Arc<AppState>) -> Result<Response, (StatusCode, String)> {
    let list = state.api.api_torrent_list();

    let torrents: Vec<TorrentStatus> = list.torrents.iter().map(|t| {
        TorrentStatus {
            hash: t.info_hash.clone(),
            name: t.name.clone().unwrap_or_default(),
            stat: TorrentStat::TorrentWorking as i32,
            stat_string: "Torrent working".to_string(),
            ..Default::default()
        }
    }).collect();

    Ok(Json(torrents).into_response())
}

async fn torrents_wipe(state: Arc<AppState>) -> Result<Response, (StatusCode, String)> {
    let list = state.api.api_torrent_list();

    // Delete each torrent
    for t in list.torrents {
        if let Some(id) = t.id {
            let _ = state.session.delete(TorrentIdOrHash::Id(id), true).await;
        }
    }

    Ok(Json(serde_json::json!({"status": "ok"})).into_response())
}

// ============================================================================
// GET /stream/*path - Stream torrent content
// ============================================================================
pub async fn stream_handler(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(params): Query<StreamQuery>,
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
    stream_content(&state, &params, &path).await
}

async fn stream_stat(
    state: &Arc<AppState>,
    params: &StreamQuery,
) -> Result<Response, (StatusCode, String)> {
    let hash = extract_hash(&params.link);

    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let handle = state.api.mgr_handle(id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let stats = handle.stats();
    let (name, file_stats, torrent_size) = get_torrent_info(&handle);

    let status = TorrentStatus {
        hash,
        name,
        stat: TorrentStat::TorrentWorking as i32,
        stat_string: "Torrent working".to_string(),
        torrent_size,
        download_speed: stats.live.as_ref().map(|l| l.download_speed.mbps * 125000.0).unwrap_or(0.0),
        upload_speed: stats.live.as_ref().map(|l| l.upload_speed.mbps * 125000.0).unwrap_or(0.0),
        file_stats,
        ..Default::default()
    };

    Ok(Json(status).into_response())
}

async fn stream_m3u(
    state: &Arc<AppState>,
    params: &StreamQuery,
    _path: &str,
) -> Result<Response, (StatusCode, String)> {
    let hash = extract_hash(&params.link);

    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let handle = state.api.mgr_handle(id)
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
) -> Result<Response, (StatusCode, String)> {
    let hash = extract_hash(&params.link);
    let index = params.index.unwrap_or(0);

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
            let response = state
                .session
                .add_torrent(add_torrent, None)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let handle = response.into_handle().ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get torrent handle".to_string(),
            ))?;

            handle.id()
        }
    };

    // Build redirect URL to rqbit's native streaming endpoint
    let redirect_url = format!("/torrents/{}/stream/{}", torrent_id, index);

    Ok(Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, redirect_url)
        .body(Body::empty())
        .unwrap())
}

// ============================================================================
// GET /play/{hash}/{id} - Play specific file from torrent
// ============================================================================
pub async fn play_handler(
    State(state): State<Arc<AppState>>,
    Path((hash, file_id)): Path<(String, usize)>,
) -> Result<Response, (StatusCode, String)> {
    let torrent_id = find_torrent_id_by_hash(&state, &hash)?;

    // Redirect to rqbit's native stream endpoint
    let redirect_url = format!("/torrents/{}/stream/{}", torrent_id, file_id);

    Ok(Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, redirect_url)
        .body(Body::empty())
        .unwrap())
}

// ============================================================================
// POST /settings - Get/set server settings
// ============================================================================
pub async fn settings_handler(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<SettingsRequest>,
) -> Result<Response, (StatusCode, String)> {
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
    Json(req): Json<ViewedRequest>,
) -> Result<Response, (StatusCode, String)> {
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
    Json(req): Json<CacheRequest>,
) -> Result<Response, (StatusCode, String)> {
    let hash = req.hash.ok_or((StatusCode::BAD_REQUEST, "hash is required".to_string()))?;

    let id = TorrentIdOrHash::try_from(hash.as_str())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let handle = state.api.mgr_handle(id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let stats = handle.stats();
    let (name, file_stats, torrent_size) = get_torrent_info(&handle);

    let status = TorrentStatus {
        hash: hash.clone(),
        name,
        stat: TorrentStat::TorrentWorking as i32,
        stat_string: "Torrent working".to_string(),
        torrent_size,
        download_speed: stats.live.as_ref().map(|l| l.download_speed.mbps * 125000.0).unwrap_or(0.0),
        upload_speed: stats.live.as_ref().map(|l| l.upload_speed.mbps * 125000.0).unwrap_or(0.0),
        file_stats,
        ..Default::default()
    };

    let cache_state = CacheState {
        hash,
        capacity: 0,
        filled: 0,
        pieces_count: 0,
        pieces_length: 0,
        torrent: Some(status),
    };

    Ok(Json(cache_state).into_response())
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
    let handle = state.api.mgr_handle(id)
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
        .ok_or((StatusCode::NOT_FOUND, format!("Torrent not found: {}", hash)))
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
                        id: id as i32,
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
