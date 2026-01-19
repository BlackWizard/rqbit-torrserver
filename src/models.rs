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

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}
fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}
fn is_empty_string(v: &String) -> bool {
    v.is_empty()
}
fn is_empty_vec<T>(v: &Vec<T>) -> bool {
    v.is_empty()
}

/// Full torrent status response
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TorrentStatus {
    pub title: String,
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub category: String,
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub poster: String,
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub data: String,
    pub timestamp: i64,
    pub name: String,
    pub hash: String,
    pub stat: i32,
    pub stat_string: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub torrent_size: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub loaded_size: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub preload_size: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub preloaded_bytes: i64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub download_speed: f64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub upload_speed: f64,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub total_peers: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub active_peers: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub pending_peers: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub half_open_peers: i32,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub connected_seeders: i32,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub bytes_read: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub bytes_read_data: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub bytes_read_useful_data: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub bytes_written: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub bytes_written_data: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub chunks_read: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub chunks_read_useful: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub chunks_read_wasted: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub chunks_written: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub pieces_dirtied_good: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub pieces_dirtied_bad: i64,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub duration_seconds: f64,
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub bit_rate: String,
    #[serde(default, skip_serializing_if = "is_empty_vec")]
    pub file_stats: Vec<TorrentFileStat>,
}

/// Settings response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BTSets {
    pub cache_size: i64,
    #[serde(rename = "ReaderReadAHead")]
    pub reader_read_a_head: i32,
    pub preload_cache: i32,
    pub use_disk: bool,
    pub torrents_save_path: String,
    pub remove_cache_on_drop: bool,
    pub force_encrypt: bool,
    pub retrackers_mode: i32,
    pub torrent_disconnect_timeout: i32,
    pub enable_debug: bool,
    #[serde(rename = "EnableDLNA")]
    pub enable_dlna: bool,
    pub friendly_name: String,
    pub enable_rutor_search: bool,
    pub enable_torznab_search: bool,
    #[serde(rename = "TorznabUrls")]
    pub torznab_urls: Option<Vec<String>>,
    #[serde(rename = "EnableIPv6")]
    pub enable_ipv6: bool,
    #[serde(rename = "DisableTCP")]
    pub disable_tcp: bool,
    #[serde(rename = "DisableUTP")]
    pub disable_utp: bool,
    #[serde(rename = "DisableUPNP")]
    pub disable_upnp: bool,
    #[serde(rename = "DisableDHT")]
    pub disable_dht: bool,
    #[serde(rename = "DisablePEX")]
    pub disable_pex: bool,
    pub disable_upload: bool,
    pub download_rate_limit: i32,
    pub upload_rate_limit: i32,
    pub connections_limit: i32,
    pub peers_listen_port: i32,
    pub ssl_port: i32,
    pub ssl_cert: String,
    pub ssl_key: String,
    pub responsive_mode: bool,
    #[serde(rename = "ShowFSActiveTorr")]
    pub show_fs_active_torr: bool,
    #[serde(rename = "StoreSettingsInJson")]
    pub store_settings_in_json: bool,
    #[serde(rename = "StoreViewedInJson")]
    pub store_viewed_in_json: bool,
}

impl Default for BTSets {
    fn default() -> Self {
        Self {
            cache_size: 1073741824, // 1 GB
            reader_read_a_head: 90,
            preload_cache: 5,
            use_disk: false,
            torrents_save_path: String::new(),
            remove_cache_on_drop: false,
            force_encrypt: false,
            retrackers_mode: 1,
            torrent_disconnect_timeout: 30,
            enable_debug: false,
            enable_dlna: true,
            friendly_name: "TorrServer".to_string(),
            enable_rutor_search: true,
            enable_torznab_search: false,
            torznab_urls: None,
            enable_ipv6: false,
            disable_tcp: false,
            disable_utp: false,
            disable_upnp: false,
            disable_dht: false,
            disable_pex: false,
            disable_upload: false,
            download_rate_limit: 0,
            upload_rate_limit: 512,
            connections_limit: 25,
            peers_listen_port: 0,
            ssl_port: 0,
            ssl_cert: String::new(),
            ssl_key: String::new(),
            responsive_mode: true,
            show_fs_active_torr: false,
            store_settings_in_json: false,
            store_viewed_in_json: false,
        }
    }
}

/// Viewed item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Viewed {
    pub hash: String,
    pub file_index: i32,
}

/// Piece state for cache
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PieceState {
    pub id: i32,
    pub length: i64,
    pub size: i64,
    pub completed: bool,
    pub priority: i32,
}

/// Reader state for cache
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReaderState {
    pub start: i32,
    pub end: i32,
    pub reader: i32,
}

/// Cache state response
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CacheState {
    pub hash: String,
    pub capacity: i64,
    pub filled: i64,
    pub pieces_length: i64,
    pub pieces_count: i32,
    pub torrent: Option<TorrentStatus>,
    pub pieces: std::collections::HashMap<String, PieceState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readers: Vec<ReaderState>,
}
