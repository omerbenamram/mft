# libewf-written fixtures

Small images written by libewf's `ewfacquire` (version 20140814), kept here so the reader is
checked against a second implementation. `ewfverify` passes on each of them.

The files carry a `.bin` suffix so they stay out of Git LFS; the tests copy them to a temporary
directory under their real name before opening them.

The media is 20 sectors of 512 bytes (10,240 bytes, MD5 `cd88c8f3f421052786eb40f50117474c`) acquired
with 16 sectors per chunk, so the second and last chunk holds only 4 sectors. The content is the
line `sector %05d line %07d of the partial-last-chunk fixture\n` repeated, where the first number
is the sector the line starts in and the second counts lines from 0, cut at 10,240 bytes.

```sh
ewfacquire -u -q -f <format> -c <compression> -b 16 -S 1048576 -t libewf_<format>_<compression> partial.raw
```

| File | `-f` | `-c` |
|------|------|------|
| `libewf_encase6_fast.E01.bin` | `encase6` | `fast` |
| `libewf_encase6_none.E01.bin` | `encase6` | `none` |
