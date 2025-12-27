use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tempfile::Builder;

pub const CONFIG_ENV_VAR: &str = "NTFS_EXPLORER_UI_STATE";

fn default_nav_width_px() -> i32 {
    280
}
fn default_col_modified_px() -> i32 {
    220
}
fn default_col_type_px() -> i32 {
    120
}
fn default_col_size_px() -> i32 {
    120
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiState {
    #[serde(default = "default_nav_width_px")]
    pub nav_width_px: i32,

    #[serde(default = "default_col_modified_px")]
    pub col_modified_px: i32,
    #[serde(default = "default_col_type_px")]
    pub col_type_px: i32,
    #[serde(default = "default_col_size_px")]
    pub col_size_px: i32,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            nav_width_px: default_nav_width_px(),
            col_modified_px: default_col_modified_px(),
            col_type_px: default_col_type_px(),
            col_size_px: default_col_size_px(),
        }
    }
}

fn home_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        env::var_os("HOME").map(PathBuf::from)
    }
}

fn user_config_dir() -> Option<PathBuf> {
    if cfg!(target_os = "windows") {
        let base = env::var_os("APPDATA")
            .or_else(|| env::var_os("LOCALAPPDATA"))
            .map(PathBuf::from)?;
        return Some(base.join("NTFS Explorer"));
    }

    if cfg!(target_os = "macos") {
        let home = home_dir()?;
        return Some(
            home.join("Library")
                .join("Application Support")
                .join("NTFS Explorer"),
        );
    }

    // Linux / other unix: XDG_CONFIG_HOME or ~/.config
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|h| h.join(".config")))?;
    Some(base.join("ntfs-explorer"))
}

fn config_path() -> Option<PathBuf> {
    if let Some(p) = env::var_os(CONFIG_ENV_VAR) {
        return Some(PathBuf::from(p));
    }
    user_config_dir().map(|d| d.join("ui_state.json"))
}

pub fn load_ui_state() -> UiState {
    let Some(path) = config_path() else {
        return UiState::default();
    };
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return UiState::default(),
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save_ui_state(state: UiState) -> Result<(), String> {
    let Some(path) = config_path() else {
        return Ok(());
    };
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create config dir {dir:?}: {e}"))?;
    }

    let data = serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?;
    atomic_write(&path, &data).map_err(|e| format!("write {path:?}: {e}"))?;
    Ok(())
}

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    // Use the ecosystem to create a unique temp file safely (same directory => same filesystem),
    // then persist it to the target path. `tempfile`'s `persist` will atomically replace an
    // existing destination file where supported (including Windows).
    let mut tmp = Builder::new()
        .prefix(".ui_state.")
        .suffix(".tmp")
        .tempfile_in(dir)?;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;

    // Close the file handle before persisting (required on Windows).
    tmp.into_temp_path().persist(path)?;
    Ok(())
}
