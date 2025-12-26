//! Dokan frontend (Windows) for mounting an NTFS image via the mount-agnostic [`super::vfs::Vfs`].
//!
//! This is intentionally **read-only**.

use super::vfs::{ROOT_ENTRY_ID, Vfs};
use crate::image::ReadAt;
use crate::ntfs::Error;
use dokan::{
    CreateFileInfo, DiskSpaceInfo, Drive, FileInfo, FileSystemHandler, MountFlags, OperationError,
    OperationInfo, VolumeInfo,
};
use std::sync::Arc;
use std::time::SystemTime;
use widestring::{U16CStr, U16CString};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
};

// ZwCreateFile create dispositions (ntifs.h)
const FILE_OPEN: u32 = 1;
const FILE_OPEN_IF: u32 = 3;

#[derive(Debug, Clone)]
struct NtfsDokan {
    vfs: Vfs,
}

#[derive(Debug, Clone)]
struct NtfsContext {
    entry_id: u64,
    is_dir: bool,
    stream: Option<Arc<dyn ReadAt>>,
    len: u64,
}

pub fn mount(
    vfs: Vfs,
    mount_point: &str,
    thread_count: u16,
    debug: bool,
) -> Result<(), dokan::MountError> {
    let handler = NtfsDokan { vfs };

    let mount_point =
        U16CString::from_str(mount_point).map_err(|_e| dokan::MountError::MountPointError)?;

    let mut flags = MountFlags::WRITE_PROTECT;
    if debug {
        flags |= MountFlags::DEBUG | MountFlags::STDERR;
    }

    let mut drive = Drive::new();
    drive.mount_point(&mount_point);
    drive.thread_count(thread_count);
    drive.flags(flags);

    // Informational: match the underlying NTFS parameters when available.
    let h = &handler.vfs.fs().volume().header;
    drive.sector_size(h.bytes_per_sector as u32);
    drive.allocation_unit_size(h.cluster_size);

    drive.mount(&handler)
}

impl<'a, 'b: 'a> FileSystemHandler<'a, 'b> for NtfsDokan {
    type Context = NtfsContext;

    fn create_file(
        &'b self,
        file_name: &U16CStr,
        _security_context: &dokan::DOKAN_IO_SECURITY_CONTEXT,
        _desired_access: u32,
        _file_attributes: u32,
        _share_access: u32,
        create_disposition: u32,
        _create_options: u32,
        _info: &mut OperationInfo<'a, 'b, Self>,
    ) -> Result<CreateFileInfo<Self::Context>, OperationError> {
        // Read-only: allow opening existing objects only.
        if create_disposition != FILE_OPEN && create_disposition != FILE_OPEN_IF {
            return Err(OperationError::Win32(ERROR_ACCESS_DENIED.0));
        }

        let path = normalize_dokan_path(file_name);
        let entry_id = if path == "\\" {
            ROOT_ENTRY_ID
        } else {
            self.vfs
                .resolve_path(&path)
                .map_err(|_| OperationError::Win32(ERROR_FILE_NOT_FOUND.0))?
        };

        let meta = self
            .vfs
            .metadata(entry_id)
            .map_err(|_| OperationError::Win32(ERROR_FILE_NOT_FOUND.0))?;

        let (stream, len) = if meta.is_dir {
            (None, 0)
        } else {
            let s = self
                .vfs
                .open_file_default_stream(entry_id)
                .map_err(map_ntfs_error)?;
            let len = s.len();
            (Some(s), len)
        };

        Ok(CreateFileInfo {
            context: NtfsContext {
                entry_id,
                is_dir: meta.is_dir,
                stream,
                len,
            },
            is_dir: meta.is_dir,
            new_file_created: false,
        })
    }

    fn read_file(
        &'b self,
        _file_name: &U16CStr,
        offset: i64,
        buffer: &mut [u8],
        _info: &OperationInfo<'a, 'b, Self>,
        context: &'a Self::Context,
    ) -> Result<u32, OperationError> {
        if context.is_dir {
            return Err(OperationError::Win32(ERROR_ACCESS_DENIED.0));
        }
        if offset < 0 {
            return Err(OperationError::Win32(ERROR_INVALID_PARAMETER.0));
        }
        let Some(stream) = context.stream.as_ref() else {
            return Err(OperationError::Win32(ERROR_ACCESS_DENIED.0));
        };

        let off = offset as u64;
        if off >= context.len || buffer.is_empty() {
            return Ok(0);
        }

        let want = (buffer.len() as u64).min(context.len - off) as usize;
        stream
            .read_exact_at(off, &mut buffer[..want])
            .map_err(|e| OperationError::Win32(map_io_error_to_win32(e).0))?;
        Ok(want as u32)
    }

    fn get_file_information(
        &'b self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'a, 'b, Self>,
        context: &'a Self::Context,
    ) -> Result<FileInfo, OperationError> {
        let meta = self
            .vfs
            .metadata(context.entry_id)
            .map_err(map_ntfs_error)?;

        let attributes = if meta.is_dir {
            FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_READONLY.0
        } else {
            FILE_ATTRIBUTE_NORMAL.0 | FILE_ATTRIBUTE_READONLY.0
        };

        Ok(FileInfo {
            attributes,
            creation_time: meta.created,
            last_access_time: meta.accessed,
            last_write_time: meta.modified,
            file_size: meta.size,
            number_of_links: 1,
            file_index: context.entry_id,
        })
    }

    fn find_files(
        &'b self,
        _file_name: &U16CStr,
        mut fill_find_data: impl FnMut(&dokan::FindData) -> Result<(), dokan::FillDataError>,
        _info: &OperationInfo<'a, 'b, Self>,
        context: &'a Self::Context,
    ) -> Result<(), OperationError> {
        if !context.is_dir {
            return Err(OperationError::Win32(ERROR_ACCESS_DENIED.0));
        }

        // Include dot entries (helps some callers).
        for name in [".", ".."] {
            let fd = dokan::FindData {
                attributes: FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_READONLY.0,
                creation_time: SystemTime::UNIX_EPOCH,
                last_access_time: SystemTime::UNIX_EPOCH,
                last_write_time: SystemTime::UNIX_EPOCH,
                file_size: 0,
                file_name: U16CString::from_str(name)
                    .map_err(|_| OperationError::Win32(ERROR_INVALID_PARAMETER.0))?,
            };
            fill_find_data(&fd)?;
        }

        let entries = self.vfs.readdir(context.entry_id).map_err(map_ntfs_error)?;
        for e in entries {
            if e.name == "." || e.name == ".." {
                continue;
            }
            let meta = self.vfs.metadata(e.entry_id).map_err(map_ntfs_error)?;

            let attributes = if meta.is_dir {
                FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_READONLY.0
            } else {
                FILE_ATTRIBUTE_NORMAL.0 | FILE_ATTRIBUTE_READONLY.0
            };

            let fd = dokan::FindData {
                attributes,
                creation_time: meta.created,
                last_access_time: meta.accessed,
                last_write_time: meta.modified,
                file_size: meta.size,
                file_name: U16CString::from_str(&e.name)
                    .map_err(|_| OperationError::Win32(ERROR_INVALID_PARAMETER.0))?,
            };
            fill_find_data(&fd)?;
        }

        Ok(())
    }

    fn get_disk_free_space(
        &'b self,
        _info: &OperationInfo<'a, 'b, Self>,
    ) -> Result<DiskSpaceInfo, OperationError> {
        let h = &self.vfs.fs().volume().header;
        let bytes = h.volume_size_bytes();
        Ok(DiskSpaceInfo {
            byte_count: bytes,
            free_byte_count: 0,
            available_byte_count: 0,
        })
    }

    fn get_volume_information(
        &'b self,
        _info: &OperationInfo<'a, 'b, Self>,
    ) -> Result<VolumeInfo, OperationError> {
        let h = &self.vfs.fs().volume().header;
        let name = U16CString::from_str("ntfs")
            .map_err(|_| OperationError::Win32(ERROR_INVALID_PARAMETER.0))?;
        let fs_name = U16CString::from_str("NTFS")
            .map_err(|_| OperationError::Win32(ERROR_INVALID_PARAMETER.0))?;

        Ok(VolumeInfo {
            name,
            serial_number: (h.volume_serial_number & 0xffff_ffff) as u32,
            max_component_length: 255,
            fs_flags: 0,
            fs_name,
        })
    }
}

fn normalize_dokan_path(s: &U16CStr) -> String {
    // Dokan passes paths with a leading backslash. Keep NTFS path semantics.
    let mut p = s.to_string_lossy().to_string();
    if p.is_empty() {
        p.push('\\');
    }
    if !p.starts_with('\\') {
        p.insert(0, '\\');
    }
    p
}

fn map_ntfs_error(e: Error) -> OperationError {
    match e {
        Error::NotFound { .. } => OperationError::Win32(ERROR_FILE_NOT_FOUND.0),
        Error::Unsupported { .. } => OperationError::Win32(ERROR_ACCESS_DENIED.0),
        Error::Io(ioe) => OperationError::Win32(map_io_error_to_win32(ioe).0),
        _ => OperationError::Win32(ERROR_ACCESS_DENIED.0),
    }
}

fn map_io_error_to_win32(e: std::io::Error) -> windows::Win32::Foundation::WIN32_ERROR {
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_GEN_FAILURE, ERROR_INVALID_PARAMETER,
    };

    match e.kind() {
        std::io::ErrorKind::NotFound => ERROR_FILE_NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => ERROR_ACCESS_DENIED,
        std::io::ErrorKind::InvalidInput => ERROR_INVALID_PARAMETER,
        _ => ERROR_GEN_FAILURE,
    }
}
