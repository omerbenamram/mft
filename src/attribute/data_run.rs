use serde::Serialize;

// adapted from https://github.com/rkapl/ntfs-reclaim/blob/a68e87b21c12631311fc3f279f5b03bd8f23d57b/src/data_runs.rs
// original didn't support sparse clusters

#[derive(Serialize, Debug, Copy, Clone, Eq, PartialEq)]
pub enum RunType {
    Standard,
    Sparse,
}

#[derive(Serialize, Debug, Copy, Clone, Eq, PartialEq)]
pub struct DataRun {
    pub lcn_offset: u64,
    pub lcn_length: u64,
    pub run_type: RunType
}

fn decode_run_value<T: Iterator<Item = u8>>(it: &mut T, bytes: u8) -> Option<u64> {
    let mut acc = 0u64;
    for _ in 0..bytes {
        let v = it.next()?;
        acc = (acc >> 8) | ((v as u64) << 56);
    }
    acc >>= (8 - bytes) * 8;
    Some(acc)
}

fn decode_run_svalue<T: Iterator<Item = u8>>(it: &mut T, bytes: u8) -> Option<i64> {
    let mut acc = decode_run_value(it, bytes)? as i64;
    // sign extend
    acc <<= (8 - bytes) * 8;
    acc >>= (8 - bytes) * 8;
    Some(acc)
}

pub fn decode_data_runs(runs: &[u8]) -> Option<Vec<DataRun>> {
    let mut it = runs.iter().copied();
    let mut out: Vec<DataRun> = Vec::new();

    loop {
        let h = it.next()?;
        if h == 0 {
            break;
        }
        let offset_size = (h & 0xF0) >> 4;
        let length_size =  h & 0x0F;
        if offset_size > 8 || length_size > 8 {
            return None
        }
        let length  = decode_run_value(&mut it, length_size)?;
        let abs_offset;
        let run_type;
        if offset_size != 0 { // offset_size of 0 == sparse cluster
            if let Some(last) = out.last() {
                let rel_offset  = decode_run_svalue(&mut it, offset_size)?;
                abs_offset = (last.lcn_offset as i64 + rel_offset) as u64;
            } else {
                abs_offset = decode_run_value(&mut it, offset_size)?;
            }
            run_type = RunType::Standard;
        }
        else {
            abs_offset = 0;
            run_type = RunType::Sparse;
        }
        out.push(DataRun {
            lcn_offset: abs_offset,
            lcn_length: length,
            run_type
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_decode() {
        assert_eq!(decode_run_value(&mut vec![0x34, 0x56].into_iter(), 2), Some(0x5634));
        assert_eq!(decode_run_svalue(&mut vec![0xE0].into_iter(), 1), Some(-0x20));
        assert_eq!(decode_run_svalue(&mut vec![0xE0].into_iter(), 2), None);
    }
}
