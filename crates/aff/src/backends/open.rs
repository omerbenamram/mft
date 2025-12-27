use crate::Result;
use crate::backends::backend::Backend;
use crate::backends::{ContainerKind, Segment};
use forensic_image::ReadAt;
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use crate::backends::afd::AfdImage;
use crate::backends::aff1::Aff1Image;
use crate::backends::afm::AfmImage;

/// Open options for AFF containers.
///
/// This type will expand as more AFFLIB-compatible features are ported (AFM/AFD, crypto, etc.).
#[derive(Debug, Clone)]
pub struct AffOpenOptions {
    /// Optional passphrase for decrypting `affkey_aes256` + `/aes256` segments.
    pub passphrase: Option<String>,

    /// Optional PEM private key path used to unseal `affkey_evp%d` segments.
    pub unseal_keyfile: Option<std::path::PathBuf>,

    /// If true, enable auto-decryption of `/aes256` segments (when a key is available).
    pub auto_decrypt: bool,

    /// Number of decompressed pages to cache in memory for page-based containers (AFF1/AFD).
    ///
    /// This is a performance knob; it does not affect correctness.
    pub page_cache_pages: usize,
}

impl AffOpenOptions {
    /// Creates a new set of open options.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::AffOpenOptions;
    ///
    /// let opts = AffOpenOptions::new();
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn new() -> Self {
        Self {
            passphrase: None,
            unseal_keyfile: None,
            auto_decrypt: true,
            page_cache_pages: 2,
        }
    }

    /// Opens an AFF-like container from a path and returns an [`AffImage`].
    ///
    /// The backend is determined from the on-disk content and/or extension.
    ///
    /// ## Examples
    ///
    /// ```no_run
    /// use aff::AffOpenOptions;
    ///
    /// let img = AffOpenOptions::new().open("image.aff")?;
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn open(&self, path: impl AsRef<Path>) -> Result<AffImage> {
        AffImage::open_with(path, self)
    }
}

impl Default for AffOpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// A read-only random-access view over an AFF-like container.
///
/// The concrete backend is selected automatically on open.
#[derive(Clone)]
pub struct AffImage {
    inner: Arc<dyn Backend>,
}

impl std::fmt::Debug for AffImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AffImage")
            .field("kind", &self.kind())
            .field("len", &self.len())
            .field("page_size", &self.page_size())
            .finish()
    }
}

impl AffImage {
    /// Opens an AFF-like container from a path.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::AffImage;
    /// use forensic_image::ReadAt;
    ///
    /// let img = AffImage::open("image.aff")?;
    /// println!("len={}", img.len());
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(path, &AffOpenOptions::new())
    }

    /// Opens an AFF-like container from a path using [`AffOpenOptions`].
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::AffOpenOptions;
    ///
    /// let mut opts = AffOpenOptions::new();
    /// opts.passphrase = Some("password".to_string());
    /// let img = opts.open("encrypted.aff")?;
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn open_with(path: impl AsRef<Path>, opts: &AffOpenOptions) -> Result<Self> {
        let path = path.as_ref();

        let data: Arc<dyn Backend> = if path.is_dir() {
            Arc::new(AfdImage::open_with(path, opts.page_cache_pages)?)
        } else {
            // Prefer content sniffing when possible.
            let mut header = [0u8; 8];
            let mut f = std::fs::File::open(path)?;
            let n = f.read(&mut header)?;
            drop(f);

            if n == header.len() && header == *crate::format::AFF1_HEADER {
                // `.afm` is also an AFF1 container, but AFM has additional split-raw semantics.
                // Use extension as a disambiguator if present.
                match path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                {
                    "afm" | "AFM" => Arc::new(AfmImage::open_with(path, opts.page_cache_pages)?),
                    _ => Arc::new(Aff1Image::open_with(path, opts.page_cache_pages)?),
                }
            } else {
                match path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                {
                    "afm" | "AFM" => Arc::new(AfmImage::open_with(path, opts.page_cache_pages)?),
                    "aff" | "AFF" => Arc::new(Aff1Image::open_with(path, opts.page_cache_pages)?),
                    other => {
                        return Err(crate::Error::Unsupported {
                            what: format!("unknown AFF container extension: {other}"),
                        });
                    }
                }
            }
        };

        // Wrap with crypto layer if enabled (feature-gated).
        #[cfg(feature = "crypto")]
        {
            let data = crate::crypto::wrap_backend(data, opts)?;
            Ok(Self { inner: data })
        }
        #[cfg(not(feature = "crypto"))]
        {
            let _ = opts;
            Ok(Self { inner: data })
        }
    }

    /// Returns the container kind backing this image.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::AffImage;
    ///
    /// let img = AffImage::open("image.aff")?;
    /// println!("{:?}", img.kind());
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn kind(&self) -> ContainerKind {
        self.inner.kind()
    }

    /// Returns the natural page size for this container, if applicable.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::AffImage;
    ///
    /// let img = AffImage::open("image.aff")?;
    /// println!("pagesize={}", img.page_size());
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn page_size(&self) -> usize {
        self.inner.page_size()
    }

    /// Returns `true` if a segment exists.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::AffImage;
    ///
    /// let img = AffImage::open("image.aff")?;
    /// if img.has_segment("imagesize")? {
    ///     println!("has imagesize");
    /// }
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn has_segment(&self, name: &str) -> std::io::Result<bool> {
        Ok(self.inner.read_segment(name)?.is_some())
    }

    /// Lists segment names present in this container.
    ///
    /// Note: some backends intentionally only list *metadata* segments (e.g. AFM)
    /// to avoid materializing extremely large page lists.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::AffImage;
    ///
    /// let img = AffImage::open("image.aff")?;
    /// let names = img.segment_names();
    /// assert!(names.iter().any(|n| n == "pagesize"));
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn segment_names(&self) -> Vec<String> {
        self.inner.segment_names()
    }

    /// Reads a segment by name.
    ///
    /// When the `crypto` feature is enabled and auto-decryption is active, this may transparently
    /// return a decrypted view of `"{name}/aes256"` as `name`, matching AFFLIB behavior.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::AffImage;
    ///
    /// let img = AffImage::open("image.aff")?;
    /// if let Some(seg) = img.read_segment("pagesize")? {
    ///     println!("pagesize arg={}", seg.arg);
    /// }
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn read_segment(&self, name: &str) -> std::io::Result<Option<Segment>> {
        self.inner.read_segment(name)
    }
}

impl ReadAt for AffImage {
    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_exact_at(offset, buf)
    }
}
