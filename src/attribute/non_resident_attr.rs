use crate::attribute::data_run::{DataRun, decode_data_runs};
use crate::attribute::header::{MftAttributeHeader, NonResidentHeader};
use crate::err::{Error, Result};

use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};

#[derive(Serialize, Clone, Debug)]
pub struct NonResidentAttr {
    pub data_runs: Vec<DataRun>,
}

impl NonResidentAttr {
    pub fn from_stream<S: Read + Seek>(
        stream: &mut S,
        header: &MftAttributeHeader,
        resident: &NonResidentHeader,
    ) -> Result<Self> {
        if resident.datarun_offset as u32 > header.record_length {
            return Err(Error::Any {
                detail: format!(
                    "datarun offset ({}) exceeds record length ({})",
                    resident.datarun_offset, header.record_length
                ),
            });
        }

        let data_run_bytes_count =
            (header.record_length - u32::from(resident.datarun_offset)) as usize;

        if data_run_bytes_count == 0 {
            return Ok(Self {
                data_runs: Vec::new(),
            });
        }

        let mut data_run_bytes = vec![0_u8; data_run_bytes_count];

        stream.seek(SeekFrom::Start(
            header.start_offset + u64::from(resident.datarun_offset),
        ))?;
        stream.read_exact(&mut data_run_bytes)?;

        if let Some(data_runs) = decode_data_runs(&data_run_bytes) {
            Ok(Self { data_runs })
        } else {
            Err(Error::FailedToDecodeDataRuns {
                bad_data_runs: data_run_bytes,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::data_run::RunType;
    use crate::attribute::header::ResidentialHeader;
    use crate::attribute::{AttributeDataFlags, MftAttributeType};
    use std::io::Cursor;

    fn build_header(
        resident: &NonResidentHeader,
        record_length: u32,
        start_offset: u64,
    ) -> MftAttributeHeader {
        MftAttributeHeader {
            type_code: MftAttributeType::DATA,
            record_length,
            form_code: 1,
            residential_header: ResidentialHeader::NonResident(resident.clone()),
            name_size: 0,
            name_offset: None,
            data_flags: AttributeDataFlags::empty(),
            instance: 0,
            name: String::new(),
            start_offset,
        }
    }

    #[test]
    fn decodes_sparse_run_even_when_valid_length_zero() {
        // Valid per NTFS spec: mapping pairs may exist while ValidDataLength == 0,
        // e.g. after FSCTL_SET_ZERO_DATA on a sparse stream.
        let data_runs = vec![0x01, 0x08, 0x00]; // sparse run, length 8 clusters
        let mut cursor = Cursor::new(data_runs.clone());

        let resident = NonResidentHeader {
            vnc_first: 0,
            vnc_last: 0,
            datarun_offset: 0,
            unit_compression_size: 0,
            padding: 0,
            allocated_length: 4096,
            file_size: 4096,
            valid_data_length: 0,
            total_allocated: None,
        };
        let header = build_header(&resident, data_runs.len() as u32, 0);

        let parsed = NonResidentAttr::from_stream(&mut cursor, &header, &resident).unwrap();

        assert_eq!(parsed.data_runs.len(), 1);
        assert_eq!(parsed.data_runs[0].run_type, RunType::Sparse);
        assert_eq!(parsed.data_runs[0].lcn_length, 8);
    }

    #[test]
    fn returns_empty_when_mapping_pairs_section_empty() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let resident = NonResidentHeader {
            vnc_first: 0,
            vnc_last: 0,
            datarun_offset: 8,
            unit_compression_size: 0,
            padding: 0,
            allocated_length: 0,
            file_size: 0,
            valid_data_length: 0,
            total_allocated: None,
        };
        let header = build_header(&resident, resident.datarun_offset as u32, 0);

        let parsed = NonResidentAttr::from_stream(&mut cursor, &header, &resident).unwrap();
        assert!(parsed.data_runs.is_empty());
    }
}
