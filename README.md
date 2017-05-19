# RustyMft
MFT to JSON

## Example output
``` json
{
  "header": {
    "signature": 1162627398,
    "usa_offset": 48,
    "usa_size": 3,
    "logfile_sequence_number": "53754616884",
    "sequence": 5,
    "hard_link_count": 2,
    "fst_attr_offset": 56,
    "flags": "ALLOCATED",
    "entry_size_real": 480,
    "entry_size_allocated": 1024,
    "base_reference": {
      "reference": "0",
      "entry": 0,
      "sequence": 0
    },
    "next_attribute_id": 5,
    "record_number": 47932,
    "update_sequence_value": 0,
    "entry_reference": {
      "reference": "1407374883601212",
      "entry": 47932,
      "sequence": 5
    }
  },
  "attr_standard_info": [{
    "created": "2013-10-22 16:31:15.796",
    "modified": "2013-10-22 16:39:29.450",
    "mft_modified": "2013-10-23 02:56:59.811",
    "accessed": "2013-10-22 16:31:15.796",
    "file_flags": 8224,
    "max_version": 0,
    "version": 0,
    "class_id": 0,
    "owner_id": 0,
    "security_id": 2604,
    "quota": "0",
    "usn": "20377883648"
  }],
  "attr_filename": [{
    "parent": {
      "reference": "562949953700461",
      "entry": 279149,
      "sequence": 2
    },
    "created": "2013-10-22 16:31:15.796",
    "modified": "2013-10-22 16:31:15.796",
    "mft_modified": "2013-10-22 16:31:15.796",
    "accessed": "2013-10-22 16:31:15.796",
    "logical_size": "0",
    "physical_size": "0",
    "flags": 8224,
    "reparse_value": 0,
    "name_length": 11,
    "namespace": 2,
    "name": "SDELET~1.PF",
    "fullname": "Windows/Prefetch/SDELET~1.PF"
  },
  {
    "parent": {
      "reference": "562949953700461",
      "entry": 279149,
      "sequence": 2
    },
    "created": "2013-10-22 16:31:15.796",
    "modified": "2013-10-22 16:31:15.796",
    "mft_modified": "2013-10-22 16:31:15.796",
    "accessed": "2013-10-22 16:31:15.796",
    "logical_size": "0",
    "physical_size": "0",
    "flags": 8224,
    "reparse_value": 0,
    "name_length": 23,
    "namespace": 1,
    "name": "SDELETE.EXE-88F94BEB.pf",
    "fullname": "Windows/Prefetch/SDELETE.EXE-88F94BEB.pf"
  }]
}
```
