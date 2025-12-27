# `forensic-image` — shared random-access trait

This crate provides a tiny abstraction (`ReadAt`) for random-access reads over disk-image-like
sources (raw files, AFF, EWF, etc.).

## Example

```rust
use forensic_image::ReadAt;
use std::sync::Arc;

# fn open_some_image() -> Arc<dyn ReadAt> { todo!() }
let img = open_some_image();
let mut sector0 = [0u8; 512];
img.read_exact_at(0, &mut sector0)?;
# Ok::<(), std::io::Error>(())
```


