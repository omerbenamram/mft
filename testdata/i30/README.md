# $I30 index record samples

`narcos-windows.I30` is the `$INDEX_ALLOCATION:$I30` stream (four 4 KiB `INDX` records) of `C:\Windows` on the main
NTFS volume of the 2019 Narcos scenario image (Digital Corpora, `Narcos-CCleaner.E01`, Windows 10). Its slack holds
the names of deleted files, including the `ZZZZZZZZ.ZZZ` names CCleaner's wipe leaves; The Sleuth Kit's `fls -d`
lists `DtcInstall.log`, `setuperr.log` and the two long `ZZZ` names from it.
