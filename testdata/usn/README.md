# USN change journal samples

`narcos-head.J` is the first 32 KiB of `$Extend\$UsnJrnl:$J` from the main NTFS volume of the 2019 Narcos
scenario image (Digital Corpora, `Narcos-CCleaner.E01`, Windows 10), behind 8 KiB of zeros that stand in for
the stream's sparse start. On the volume, the first byte after the zeros is USN 67108864.
