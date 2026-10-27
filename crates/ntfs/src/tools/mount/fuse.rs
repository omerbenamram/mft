//! FUSE frontend (Unix) for mounting an NTFS image via the mount-agnostic [`super::vfs::Vfs`].
//!
//! This is intentionally **read-only**.

use super::vfs::{ROOT_ENTRY_ID, Vfs};
use crate::image::ReadAt;
use crate::ntfs::Error;
use crate::ntfs::filesystem::is_dot_dir_entry;
use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    LockOwner, MountOption, OpenAccMode, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, Request,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

pub fn mount(vfs: Vfs, mountpoint: &Path) -> std::io::Result<()> {
    // Keep options minimal and safe. Let the user configure kernel-side permission checks.
    let mut config = Config::default();
    config.mount_options = vec![MountOption::RO, MountOption::FSName("ntfs".to_string())];
    fuser::mount(NtfsFuse::new(vfs), mountpoint, &config)
}

struct NtfsFuse {
    vfs: Vfs,
    // `Filesystem` callbacks take `&self`, so the mutable maps live behind a lock.
    state: Mutex<FuseState>,
}

struct FuseState {
    // Stable inode mapping (required because FUSE expects root inode = 1).
    entry_to_ino: HashMap<u64, u64>,
    ino_to_entry: HashMap<u64, u64>,
    next_ino: u64,

    // Open file handles -> stream
    fh_to_stream: HashMap<u64, Arc<dyn ReadAt>>,
    next_fh: u64,
}

impl NtfsFuse {
    fn new(vfs: Vfs) -> Self {
        let mut entry_to_ino = HashMap::new();
        let mut ino_to_entry = HashMap::new();

        entry_to_ino.insert(ROOT_ENTRY_ID, 1);
        ino_to_entry.insert(1, ROOT_ENTRY_ID);

        Self {
            vfs,
            state: Mutex::new(FuseState {
                entry_to_ino,
                ino_to_entry,
                next_ino: 2,
                fh_to_stream: HashMap::new(),
                next_fh: 1,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, FuseState> {
        // The maps stay consistent even if a callback panicked while holding the lock.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn ino_to_entry_id(&self, ino: INodeNo) -> Option<u64> {
        self.state().ino_to_entry.get(&ino.0).copied()
    }

    fn entry_id_to_ino(&self, entry_id: u64) -> INodeNo {
        let mut state = self.state();
        if let Some(&ino) = state.entry_to_ino.get(&entry_id) {
            return INodeNo(ino);
        }

        let ino = state.next_ino;
        state.next_ino = state.next_ino.saturating_add(1);

        state.entry_to_ino.insert(entry_id, ino);
        state.ino_to_entry.insert(ino, entry_id);
        INodeNo(ino)
    }

    fn to_file_attr(
        &self,
        ino: INodeNo,
        meta: super::vfs::EntryMetadata,
        req: &Request,
    ) -> FileAttr {
        let kind = if meta.is_dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        };

        let perm = if meta.is_dir { 0o555 } else { 0o444 };
        let size = meta.size;
        let blocks = size.div_ceil(512);

        FileAttr {
            ino,
            size,
            blocks,
            atime: meta.accessed,
            mtime: meta.modified,
            ctime: meta.mft_modified,
            crtime: meta.created,
            kind,
            perm,
            nlink: if meta.is_dir { 2 } else { 1 },
            uid: req.uid(),
            gid: req.gid(),
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}

impl Filesystem for NtfsFuse {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_entry) = self.ino_to_entry_id(parent) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if name.is_empty() || name == "." {
            let ino = parent;
            let Ok(meta) = self.vfs.metadata(parent_entry) else {
                reply.error(Errno::EIO);
                return;
            };
            let attr = self.to_file_attr(ino, meta, req);
            reply.entry(&TTL, &attr, Generation(0));
            return;
        }

        match self.vfs.lookup(parent_entry, name) {
            Ok(child_entry) => match self.vfs.metadata(child_entry) {
                Ok(meta) => {
                    let ino = self.entry_id_to_ino(child_entry);
                    let attr = self.to_file_attr(ino, meta, req);
                    reply.entry(&TTL, &attr, Generation(0));
                }
                Err(e) => reply.error(err_to_errno(&e)),
            },
            Err(e) => reply.error(err_to_errno(&e)),
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let Some(entry_id) = self.ino_to_entry_id(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };

        match self.vfs.metadata(entry_id) {
            Ok(meta) => {
                let attr = self.to_file_attr(ino, meta, req);
                reply.attr(&TTL, &attr);
            }
            Err(e) => reply.error(err_to_errno(&e)),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(entry_id) = self.ino_to_entry_id(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };

        if flags.acc_mode() != OpenAccMode::O_RDONLY {
            reply.error(Errno::EACCES);
            return;
        }

        let Ok(meta) = self.vfs.metadata(entry_id) else {
            reply.error(Errno::EIO);
            return;
        };
        if meta.is_dir {
            reply.error(Errno::EISDIR);
            return;
        }

        match self.vfs.open_file_default_stream(entry_id) {
            Ok(stream) => {
                let mut state = self.state();
                let fh = state.next_fh;
                state.next_fh = state.next_fh.saturating_add(1);
                state.fh_to_stream.insert(fh, stream);
                reply.opened(FileHandle(fh), FopenFlags::empty());
            }
            Err(e) => reply.error(err_to_errno(&e)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        // Clone the stream out so the read itself runs without holding the lock.
        let Some(stream) = self.state().fh_to_stream.get(&fh.0).cloned() else {
            reply.error(Errno::EBADF);
            return;
        };

        let len = stream.len();
        if offset >= len {
            reply.data(&[]);
            return;
        }

        let want = (size as u64).min(len - offset);
        let mut buf = vec![0u8; want as usize];
        if let Err(e) = stream.read_exact_at(offset, &mut buf) {
            reply.error(err_to_errno(&Error::Io(e)));
            return;
        }

        reply.data(&buf);
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.state().fh_to_stream.remove(&fh.0);
        reply.ok();
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let Some(entry_id) = self.ino_to_entry_id(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.vfs.metadata(entry_id) {
            Ok(meta) if meta.is_dir => reply.opened(FileHandle(0), FopenFlags::empty()),
            Ok(_) => reply.error(Errno::ENOTDIR),
            Err(e) => reply.error(err_to_errno(&e)),
        }
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(dir_entry_id) = self.ino_to_entry_id(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };

        let Ok(meta) = self.vfs.metadata(dir_entry_id) else {
            reply.error(Errno::EIO);
            return;
        };
        if !meta.is_dir {
            reply.error(Errno::ENOTDIR);
            return;
        }

        let mut idx = 0u64;

        // offset semantics: caller passes the "next" offset to resume from.
        // We use:
        // - 1 => "."
        // - 2 => ".."
        // - 3+ => directory entries
        if offset == 0 {
            let _full = reply.add(ino, 1, FileType::Directory, ".");
            idx = 1;
        }
        if offset <= 1 {
            let _full = reply.add(ino, 2, FileType::Directory, "..");
            idx = 2;
        }

        let entries = match self.vfs.readdir(dir_entry_id) {
            Ok(v) => v,
            Err(e) => {
                reply.error(err_to_errno(&e));
                return;
            }
        };

        let mut off = 3u64;
        for e in entries {
            if is_dot_dir_entry(&e.name) {
                continue;
            }

            if off < offset {
                off += 1;
                continue;
            }

            let child_ino = self.entry_id_to_ino(e.entry_id);
            let kind = match self.vfs.metadata(e.entry_id) {
                Ok(m) => {
                    if m.is_dir {
                        FileType::Directory
                    } else {
                        FileType::RegularFile
                    }
                }
                Err(_) => FileType::RegularFile,
            };

            // `add` returns `true` if the buffer is full.
            if reply.add(child_ino, off + 1, kind, e.name) {
                break;
            }
            off += 1;
        }

        // Ensure reply is finalized.
        reply.ok();

        // Keep `req` used (some builds warn on unused in certain cfg combos).
        let _ = req.uid();
        let _ = idx;
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        // Best-effort: provide minimal statfs.
        // Values are mostly informational for read-only forensic mounts.
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }
}

fn err_to_errno(e: &Error) -> Errno {
    match e {
        Error::NotFound { .. } => Errno::ENOENT,
        Error::Unsupported { .. } => Errno::EOPNOTSUPP,
        Error::InvalidBootSector { .. } => Errno::EIO,
        Error::InvalidData { .. } => Errno::EIO,
        Error::Parse(_) => Errno::EIO,
        Error::Mft(_) => Errno::EIO,
        Error::Io(ioe) => match ioe.kind() {
            std::io::ErrorKind::NotFound => Errno::ENOENT,
            std::io::ErrorKind::PermissionDenied => Errno::EACCES,
            std::io::ErrorKind::UnexpectedEof => Errno::EIO,
            std::io::ErrorKind::InvalidInput => Errno::EINVAL,
            _ => Errno::EIO,
        },
    }
}

fn _system_time_or_epoch(x: SystemTime) -> SystemTime {
    // Placeholder for future: normalize weird timestamps if needed.
    if x == SystemTime::UNIX_EPOCH {
        UNIX_EPOCH
    } else {
        x
    }
}
