use crate::image::ReadAt;
use crate::ntfs::efs::EfsRsaKeyBag;
use crate::ntfs::filesystem::DirectoryEntry;
use crate::ntfs::{Error, FileSystem, Result};
use jiff::Timestamp;
use mft::attribute::MftAttributeType;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// NTFS root directory MFT entry id.
pub const ROOT_ENTRY_ID: u64 = 5;

#[derive(Debug, Clone)]
pub struct Vfs {
    fs: FileSystem,
    strict: bool,
    efs_keys: Option<Arc<EfsRsaKeyBag>>,
}

#[derive(Debug, Clone)]
pub struct EntryMetadata {
    pub is_dir: bool,
    pub size: u64,
    pub readonly: bool,
    pub created: SystemTime,
    pub modified: SystemTime,
    pub mft_modified: SystemTime,
    pub accessed: SystemTime,
}

impl Vfs {
    pub fn new(fs: FileSystem) -> Self {
        Self {
            fs,
            strict: false,
            efs_keys: None,
        }
    }

    pub fn fs(&self) -> &FileSystem {
        &self.fs
    }

    /// If `true`, directory traversal does **not** fall back to MFT parent-reference scans when
    /// `$I30` structures are missing/corrupt.
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// If provided, EFS-encrypted file reads are transparently decrypted.
    pub fn with_efs_keys(mut self, keys: Option<EfsRsaKeyBag>) -> Self {
        self.efs_keys = keys.map(Arc::new);
        self
    }

    pub fn root_entry_id(&self) -> u64 {
        ROOT_ENTRY_ID
    }

    pub fn resolve_path(&self, path: &str) -> Result<u64> {
        if self.strict {
            self.fs.resolve_path_strict(path)
        } else {
            self.fs.resolve_path(path)
        }
    }

    pub fn lookup(&self, dir_entry_id: u64, name: &str) -> Result<u64> {
        if self.strict {
            self.fs.lookup_in_dir_strict(dir_entry_id, name)
        } else {
            self.fs.lookup_in_dir(dir_entry_id, name)
        }
    }

    pub fn readdir(&self, dir_entry_id: u64) -> Result<Vec<DirectoryEntry>> {
        if self.strict {
            self.fs.read_dir_strict(dir_entry_id)
        } else {
            self.fs.read_dir(dir_entry_id)
        }
    }

    pub fn metadata(&self, entry_id: u64) -> Result<EntryMetadata> {
        let entry = self.fs.volume().read_mft_entry(entry_id)?;
        let is_dir = entry.is_dir();

        // Timestamps + readonly from $STANDARD_INFORMATION (strict: require it).
        let mut si = None;
        for attr in
            entry.iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
        {
            let attr = attr?;
            if let Some(x) = attr.data.into_standard_info() {
                si = Some(x);
                break;
            }
        }
        let si = si.ok_or_else(|| Error::NotFound {
            what: format!("missing $STANDARD_INFORMATION for entry {entry_id}"),
        })?;

        let readonly = si
            .file_flags
            .contains(mft::attribute::FileAttributeFlags::FILE_ATTRIBUTE_READONLY);

        let created = timestamp_to_system_time(&si.created);
        let modified = timestamp_to_system_time(&si.modified);
        let mft_modified = timestamp_to_system_time(&si.mft_modified);
        let accessed = timestamp_to_system_time(&si.accessed);

        // Use the default $DATA stream size for files; directories report 0.
        let size = if is_dir {
            0
        } else {
            // For metadata, do not require EFS keys; size is well-defined either way.
            self.fs
                .open_file_default_stream_read_at(entry_id)
                .map(|s| s.len())
                .unwrap_or(0)
        };

        Ok(EntryMetadata {
            is_dir,
            size,
            readonly,
            created,
            modified,
            mft_modified,
            accessed,
        })
    }

    /// Opens the default unnamed `$DATA` stream as a random-access reader.
    ///
    /// If the file is EFS-encrypted, this returns plaintext **only if** keys were provided via
    /// [`with_efs_keys`]. Otherwise, this returns an error.
    pub fn open_file_default_stream(&self, entry_id: u64) -> Result<Arc<dyn ReadAt>> {
        // If encrypted, we require keys (to avoid silently serving ciphertext under a mount).
        if self.fs.is_entry_efs_encrypted(entry_id)? {
            let Some(keys) = self.efs_keys.as_ref() else {
                return Err(Error::Unsupported {
                    what: "EFS-encrypted file read requires --pfx (PKCS#12)".to_string(),
                });
            };
            return self
                .fs
                .open_file_default_stream_read_at_decrypted(entry_id, keys.as_ref());
        }

        self.fs.open_file_default_stream_read_at(entry_id)
    }
}

fn timestamp_to_system_time(ts: &Timestamp) -> SystemTime {
    let secs = ts.as_second();
    let nanos = ts.subsec_nanosecond() as u32;

    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nanos)
    } else {
        // Best-effort for pre-epoch timestamps.
        let secs_abs = secs.unsigned_abs();
        UNIX_EPOCH
            .checked_sub(Duration::new(secs_abs, nanos))
            .unwrap_or(UNIX_EPOCH)
    }
}
