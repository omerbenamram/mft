# Windows 11 sample records

`win11_system.MFT` and the `win11_entry_*` files are cut from the `$MFT` of the "Bart" Windows 11 Pro
disk image:

> Nuno Mourinho, Mario Candeias and Rogerio Bravo (Instituto Politécnico de Beja), *Bart*, Zenodo,
> record 10070982, https://doi.org/10.5281/zenodo.10070982

The image is licensed under the [Creative Commons Attribution 4.0 International licence
(CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/). These files are unmodified 1024-byte records
copied out of it, so they are under the same licence, and this notice has to stay with them.

| File | Record | What it covers |
|---|---|---|
| `win11_system.MFT` | 0-33 | Every system file, including `$Secure`, `$Extend\$Quota`, `$ObjId`, `$Reparse`, `$Deleted` and `$RmMetadata\$Txf` |
| `win11_entry_40_logged_utility_stream_dsc` | 40 | `$LOGGED_UTILITY_STREAM` `$DSC` and `$TXF_DATA` |
| `win11_entry_205_ea_kernel_purge` | 205 | `$EA` with `$KERNEL.PURGE.*` cache entries |
| `win11_entry_358_appexeclink` | 358 | `notepad.exe` app execution alias |
| `win11_entry_95063_usn_journal` | 95063 | `$Extend\$UsnJrnl` with its `$J` and `$Max` streams |
| `win11_entry_100558_cloud_files_placeholder` | 100558 | OneDrive placeholder file (cloud files reparse point) |
| `win11_entry_137062_onedrive_folder` | 137062 | OneDrive folder: object id, named `$DATA` stream, `$I30` index root and cloud reparse point |
