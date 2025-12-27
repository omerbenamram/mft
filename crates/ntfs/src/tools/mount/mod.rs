//! Mount frontends (FUSE/Dokan) + a mount-agnostic VFS core.
//!
//! The goal is to keep OS-specific glue thin and concentrate NTFS-specific behavior (path
//! resolution, directory listing, file reads including compression + EFS) in `vfs`.

pub mod vfs;

#[cfg(all(feature = "fuse", target_os = "linux"))]
pub mod fuse;

#[cfg(all(feature = "dokan", windows))]
pub mod dokan;
