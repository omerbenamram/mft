//! FUSE frontend (Unix) for mounting an NTFS image via the mount-agnostic [`super::vfs::Vfs`].
//!
//! This is intentionally **read-only**.

use super::vfs::{ROOT_ENTRY_ID, Vfs};
use crate::image::ReadAt;
use crate::ntfs::Error;
use crate::ntfs::filesystem::is_dot_dir_entry;
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, Request,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

pub fn mount(vfs: Vfs, mountpoint: &Path) -> std::io::Result<()> {
    // Keep options minimal and safe. Let the user configure kernel-side permission checks.
    let opts = [MountOption::RO, MountOption::FSName("ntfs".to_string())];
    fuser::mount2(NtfsFuse::new(vfs), mountpoint, &opts)
}

#[derive(Debug)]
struct NtfsFuse {
    vfs: Vfs,

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
            entry_to_ino,
            ino_to_entry,
            next_ino: 2,
            fh_to_stream: HashMap::new(),
            next_fh: 1,
        }
    }

    fn ino_to_entry_id(&self, ino: u64) -> Option<u64> {
        self.ino_to_entry.get(&ino).copied()
    }

    fn entry_id_to_ino(&mut self, entry_id: u64) -> u64 {
        if let Some(&ino) = self.entry_to_ino.get(&entry_id) {
            return ino;
        }

        let ino = self.next_ino;
        self.next_ino = self.next_ino.saturating_add(1);

        self.entry_to_ino.insert(entry_id, ino);
        self.ino_to_entry.insert(ino, entry_id);
        ino
    }

    fn to_file_attr(
        &mut self,
        ino: u64,
        meta: super::vfs::EntryMetadata,
        req: &Request<'_>,
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
    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_entry) = self.ino_to_entry_id(parent) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(name) = name.to_str() else {
            reply.error(libc::ENOENT);
            return;
        };
        if name.is_empty() || name == "." {
            let ino = parent;
            let Ok(meta) = self.vfs.metadata(parent_entry) else {
                reply.error(libc::EIO);
                return;
            };
            let attr = self.to_file_attr(ino, meta, req);
            reply.entry(&TTL, &attr, 0);
            return;
        }

        match self.vfs.lookup(parent_entry, name) {
            Ok(child_entry) => match self.vfs.metadata(child_entry) {
                Ok(meta) => {
                    let ino = self.entry_id_to_ino(child_entry);
                    let attr = self.to_file_attr(ino, meta, req);
                    reply.entry(&TTL, &attr, 0);
                }
                Err(e) => reply.error(err_to_errno(&e)),
            },
            Err(e) => reply.error(err_to_errno(&e)),
        }
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(entry_id) = self.ino_to_entry_id(ino) else {
            reply.error(libc::ENOENT);
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

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(entry_id) = self.ino_to_entry_id(ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        if (flags & libc::O_ACCMODE) != libc::O_RDONLY {
            reply.error(libc::EACCES);
            return;
        }

        let Ok(meta) = self.vfs.metadata(entry_id) else {
            reply.error(libc::EIO);
            return;
        };
        if meta.is_dir {
            reply.error(libc::EISDIR);
            return;
        }

        match self.vfs.open_file_default_stream(entry_id) {
            Ok(stream) => {
                let fh = self.next_fh;
                self.next_fh = self.next_fh.saturating_add(1);
                self.fh_to_stream.insert(fh, stream);
                reply.opened(fh, 0);
            }
            Err(e) => reply.error(err_to_errno(&e)),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(stream) = self.fh_to_stream.get(&fh) else {
            reply.error(libc::EBADF);
            return;
        };

        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }

        let offset = offset as u64;
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
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.fh_to_stream.remove(&fh);
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let Some(entry_id) = self.ino_to_entry_id(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.vfs.metadata(entry_id) {
            Ok(meta) if meta.is_dir => reply.opened(0, 0),
            Ok(_) => reply.error(libc::ENOTDIR),
            Err(e) => reply.error(err_to_errno(&e)),
        }
    }

    fn readdir(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(dir_entry_id) = self.ino_to_entry_id(ino) else {
            reply.error(libc::ENOENT);
            return;
        };

        let Ok(meta) = self.vfs.metadata(dir_entry_id) else {
            reply.error(libc::EIO);
            return;
        };
        if !meta.is_dir {
            reply.error(libc::ENOTDIR);
            return;
        }

        let mut idx = 0i64;

        // offset semantics: caller passes the "next" offset to resume from.
        // We use:
        // - 1 => "."
        // - 2 => ".."
        // - 3+ => directory entries
        if offset <= 0 {
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

        let mut off = 3i64;
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

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        // Best-effort: provide minimal statfs.
        // Values are mostly informational for read-only forensic mounts.
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }
}

fn err_to_errno(e: &Error) -> i32 {
    match e {
        Error::NotFound { .. } => libc::ENOENT,
        Error::Unsupported { .. } => libc::EOPNOTSUPP,
        Error::InvalidBootSector { .. } => libc::EIO,
        Error::InvalidData { .. } => libc::EIO,
        Error::Parse(_) => libc::EIO,
        Error::Mft(_) => libc::EIO,
        Error::Io(ioe) => match ioe.kind() {
            std::io::ErrorKind::NotFound => libc::ENOENT,
            std::io::ErrorKind::PermissionDenied => libc::EACCES,
            std::io::ErrorKind::UnexpectedEof => libc::EIO,
            std::io::ErrorKind::InvalidInput => libc::EINVAL,
            _ => libc::EIO,
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
