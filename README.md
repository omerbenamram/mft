A fast and cross platform MFT Parser written in Rust that gives you the ability to query the records via JMES Query. Output is JSONL (http://jsonlines.org/).

```
RustyMft 0.1.0
Matthew Seyer <https://github.com/forensicmatt/RustyMft>
Parse $MFT.

USAGE:
    RustyMft.exe [FLAGS] [OPTIONS] --source <FILE>

FLAGS:
    -b, --bool_expr    JMES Query as bool only. (Prints whole record if true.)
    -h, --help         Prints help information
    -V, --version      Prints version information

OPTIONS:
    -q, --query <QUERY>    JMES Query
    -s, --source <FILE>    The source path. Can be a file or a directory.
```
