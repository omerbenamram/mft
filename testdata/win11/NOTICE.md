# Windows 11 sample records

`system.MFT` and the `entry_*` files are cut from the `$MFT` of the "Bart" Windows 11 Pro
disk image:

> Nuno Mourinho, Mario Candeias and Rogerio Bravo (Instituto Politécnico de Beja), *Bart*, Zenodo,
> record 10070982, https://doi.org/10.5281/zenodo.10070982

Copyright (c) Nuno Mourinho, Mario Candeias and Rogerio Bravo. The image is licensed under the
[Creative Commons Attribution 4.0 International licence (CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/),
which provides it as-is, without warranties (see section 5 of the licence). These files are unmodified
1024-byte records copied out of it, so they are under the same licence, and this notice has to stay with
them. They are test data for this repository only and are not part of the published `mft` crate.

| File | Record | What it covers |
|---|---|---|
| `system.MFT` | 0-33 | Every system file, including `$Secure`, `$Extend\$Quota`, `$ObjId`, `$Reparse`, `$Deleted` and `$RmMetadata\$Txf`. Records 16-23 are all zeroes in the image (reserved and never written), so tools skip them |
| `entry_40_logged_utility_stream_dsc` | 40 | `$LOGGED_UTILITY_STREAM` `$DSC` and `$TXF_DATA` |
| `entry_205_ea_kernel_purge` | 205 | `$EA` with `$KERNEL.PURGE.*` cache entries |
| `entry_358_appexeclink` | 358 | `notepad.exe` app execution alias |
| `entry_95063_usn_journal` | 95063 | `$Extend\$UsnJrnl` with its `$J` and `$Max` streams |
| `entry_100558_cloud_files_placeholder` | 100558 | OneDrive placeholder file (cloud files reparse point) |
| `entry_137062_onedrive_folder` | 137062 | OneDrive folder: object id, named `$DATA` stream, `$I30` index root and cloud reparse point |
