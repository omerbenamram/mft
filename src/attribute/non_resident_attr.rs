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
        let data_run_bytes_count =
            (header.record_length - u32::from(resident.datarun_offset)) as usize;
        let mut data_run_bytes = vec![0_u8; data_run_bytes_count];
        if resident.valid_data_length != 0 {
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
        } else {
            let data_runs = Vec::new();
            Ok(Self { data_runs })
        }
    }
}
