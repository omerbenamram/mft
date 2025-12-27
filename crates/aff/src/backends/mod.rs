//! Container backends and high-level entry points.
//!
//! This module provides the crate’s main public surface:
//! - [`AffOpenOptions`] for opening images with optional crypto configuration
//! - [`AffImage`], a read-only disk image view implementing [`forensic_image::ReadAt`]

mod afd;
mod aff1;
mod afm;
pub(crate) mod backend;
mod open;
mod split_raw;

pub use backend::{ContainerKind, Segment};
pub use open::{AffImage, AffOpenOptions};
