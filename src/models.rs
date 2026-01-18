use serde::{Deserialize, Serialize};

// ============================================================================
// Request types
// ============================================================================

/// POST /torrents request
#[derive(Debug, Deserialize)]
pub struct TorrentsRequest {
    pub action: String,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub link: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub poster: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub save_to_db: Option<bool>,
}

/// POST /settings request
#[derive(Debug, Deserialize)]
pub struct SettingsRequest {
    pub action: String,
    #[serde(default)]
    pub sets: Option<BTSets>,
}

/// POST /viewed request
#[derive(Debug, Deserialize)]
pub struct ViewedRequest {
    pub action: String,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub file_index: Option<i32>,
}

/// POST /cache request
#[derive(Debug, Deserialize)]
pub struct CacheRequest {
    pub action: Option<String>,
    pub hash: Option<String>,
}

/// GET /stream query params
#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    pub link: String,
    #[serde(default)]
    pub index: Option<usize>,
    #[serde(default)]
    pub preload: Option<String>,
    #[serde(default)]
    pub stat: Option<String>,
    #[serde(default)]
    pub save: Option<String>,
    #[serde(default)]
    pub m3u: Option<String>,
    #[serde(default)]
    pub fromlast: Option<String>,
    #[serde(default)]
    pub play: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub poster: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
}

/// GET /playlist query params
#[derive(Debug, Deserialize)]
pub struct PlaylistQuery {
    pub hash: String,
    #[serde(default)]
    pub fromlast: Option<bool>,
}

// ============================================================================
// Response types
// ============================================================================

/// Torrent status enum
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(i32)]
pub enum TorrentStat {
    TorrentAdded = 0,
    TorrentGettingInfo = 1,
    TorrentPreload = 2,
    TorrentWorking = 3,
    TorrentClosed = 4,
    TorrentInDB = 5,
}

impl Default for TorrentStat {
    fn default() -> Self {
        TorrentStat::TorrentAdded
    }
}

/// File statistics within a torrent
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TorrentFileStat {
    pub id: i32,
    pub path: String,
    pub length: i64,
}

/// Full torrent status response
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TorrentStatus {
    pub hash: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub poster: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub stat: i32,
    #[serde(default)]
    pub stat_string: String,
    #[serde(default)]
    pub torrent_size: i64,
    #[serde(default)]
    pub loaded_size: i64,
    #[serde(default)]
    pub preload_size: i64,
    #[serde(default)]
    pub preloaded_bytes: i64,
    #[serde(default)]
    pub download_speed: f64,
    #[serde(default)]
    pub upload_speed: f64,
    #[serde(default)]
    pub total_peers: i32,
    #[serde(default)]
    pub active_peers: i32,
    #[serde(default)]
    pub pending_peers: i32,
    #[serde(default)]
    pub half_open_peers: i32,
    #[serde(default)]
    pub connected_seeders: i32,
    #[serde(default)]
    pub bytes_read: i64,
    #[serde(default)]
    pub bytes_read_data: i64,
    #[serde(default)]
    pub bytes_read_useful_data: i64,
    #[serde(default)]
    pub bytes_written: i64,
    #[serde(default)]
    pub bytes_written_data: i64,
    #[serde(default)]
    pub chunks_read: i64,
    #[serde(default)]
    pub chunks_read_useful: i64,
    #[serde(default)]
    pub chunks_read_wasted: i64,
    #[serde(default)]
    pub chunks_written: i64,
    #[serde(default)]
    pub pieces_dirtied_good: i64,
    #[serde(default)]
    pub pieces_dirtied_bad: i64,
    #[serde(default)]
    pub duration_seconds: f64,
    #[serde(default)]
    pub bit_rate: String,
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default)]
    pub file_stats: Vec<TorrentFileStat>,
}

/// Settings response
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BTSets {
    #[serde(default)]
    pub cache_size: i64,
    #[serde(default)]
    pub preload_cache: i32,
    #[serde(default)]
    pub connections_limit: i32,
    #[serde(default)]
    pub disable_dht: bool,
    #[serde(default)]
    pub disable_pex: bool,
    #[serde(default)]
    pub disable_tcp: bool,
    #[serde(default)]
    pub disable_utp: bool,
    #[serde(default)]
    pub disable_upnp: bool,
    #[serde(default)]
    pub disable_upload: bool,
    #[serde(default)]
    pub download_rate_limit: i32,
    #[serde(default)]
    pub upload_rate_limit: i32,
    #[serde(default)]
    pub peers_listen_port: i32,
    #[serde(default)]
    pub enable_ipv6: bool,
    #[serde(default)]
    pub enable_dlna: bool,
    #[serde(default)]
    pub friendly_name: String,
    #[serde(default)]
    pub enable_debug: bool,
    #[serde(default)]
    pub enable_rutor_search: bool,
    #[serde(default)]
    pub enable_torznab_search: bool,
    #[serde(default)]
    pub responsive_mode: bool,
    #[serde(default)]
    pub torrent_disconnect_timeout: i32,
    #[serde(default)]
    pub force_encrypt: bool,
    #[serde(default)]
    pub retrackers_mode: i32,
    #[serde(default)]
    pub reader_read_a_head: i32,
    #[serde(default)]
    pub use_disk: bool,
    #[serde(default)]
    pub torrents_save_path: String,
    #[serde(default)]
    pub remove_cache_on_drop: bool,
    #[serde(default)]
    pub show_fs_active_torr: bool,
    #[serde(default)]
    pub ssl_port: i32,
    #[serde(default)]
    pub ssl_cert: String,
    #[serde(default)]
    pub ssl_key: String,
}

/// Viewed item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Viewed {
    pub hash: String,
    pub file_index: i32,
}

/// Cache state response
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CacheState {
    pub hash: String,
    pub capacity: i64,
    pub filled: i64,
    pub pieces_count: i32,
    pub pieces_length: i64,
    pub torrent: Option<TorrentStatus>,
}
