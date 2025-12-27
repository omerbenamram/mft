use crate::image::ReadAt;
use std::io;
use std::path::Path;

/// AFF (Advanced Forensic Format) image wrapper.
///
/// This is a thin compatibility layer over the workspace `aff` crate so existing `ntfs` callers
/// can continue using `ntfs::image::AffImage`.
#[derive(Debug, Clone)]
pub struct AffImage {
    inner: ::aff::AffImage,
}

impl AffImage {
    /// Opens an AFF-like container from a path.
    ///
    /// Currently, `ntfs` selects the AFF backend by the `.aff` extension (see `image::Image::open`),
    /// but the underlying `aff` crate also supports content sniffing.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use ntfs::image::{AffImage, ReadAt};
    ///
    /// let img = AffImage::open("disk.aff")?;
    /// let mut sector0 = [0u8; 512];
    /// img.read_exact_at(0, &mut sector0)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        ::aff::AffImage::open(path.as_ref())
            .map(|inner| Self { inner })
            .map_err(aff_error_to_io)
    }

    /// Returns the underlying AFF container kind.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use ntfs::image::AffImage;
    ///
    /// let img = AffImage::open("disk.aff")?;
    /// println!("{:?}", img.kind());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn kind(&self) -> ::aff::ContainerKind {
        self.inner.kind()
    }

    /// Returns the container page size.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use ntfs::image::AffImage;
    ///
    /// let img = AffImage::open("disk.aff")?;
    /// println!("pagesize={}", img.page_size());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn page_size(&self) -> usize {
        self.inner.page_size()
    }
}

impl ReadAt for AffImage {
    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact_at(offset, buf)
    }
}

fn aff_error_to_io(e: ::aff::Error) -> io::Error {
    match e {
        ::aff::Error::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}
