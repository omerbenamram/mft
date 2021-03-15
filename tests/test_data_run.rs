mod fixtures;

use fixtures::*;
use mft::mft::MftParser;
use mft::attribute::{MftAttribute, MftAttributeType};
use mft::attribute::data_run::{DataRun, RunType, decode_data_runs};

#[test]
fn test_runs() {
    // Examples taken from the linux-ntfs guide
    assert_eq!(
        decode_data_runs(&[0x21, 0x18, 0x34, 0x56, 0x00]),
        Some(vec![
            DataRun {lcn_length: 0x18, lcn_offset: 0x5634, run_type: RunType::Standard}
        ])
    );
    
    // this panics in the original github code
    assert_eq!(
        decode_data_runs(&[0x11, 0x30, 0x20, 0x01, 0x60, 0x11, 0x10, 0x30, 0x00]),
        Some(vec![
            DataRun {lcn_length: 0x30, lcn_offset: 0x20, run_type: RunType::Standard},
            DataRun {lcn_length: 0x60, lcn_offset: 0, run_type: RunType::Sparse},
            DataRun {lcn_length: 0x10, lcn_offset: 0x30, run_type: RunType::Standard},
        ])
    );

    assert_eq!(
        decode_data_runs(&[0x31, 0x38, 0x73, 0x25, 0x34, 0x32, 0x14, 0x01, 0xE5, 0x11, 0x02, 0x31, 0x42, 0xAA, 0x00, 0x03, 0x00]),
        Some(vec![
            DataRun {lcn_length: 0x38, lcn_offset: 0x342573, run_type: RunType::Standard},
            DataRun {lcn_length: 0x114, lcn_offset: 0x363758, run_type: RunType::Standard},
            DataRun {lcn_length: 0x42, lcn_offset: 0x393802, run_type: RunType::Standard},
        ])
    );

    assert_eq!(
        decode_data_runs(&[0x03, 0x80, 0xE4, 0x07, 0x31, 0x47, 0x62, 0x72, 0x3C, 0x31, 0x49, 0xC1, 0x9C, 0x02, 0x32, 0xA0, 0x00, 0x98, 0x80, 0xFA, 0x32, 0xA0, 0x00, 0xE4, 0xEC, 0x06, 0x31, 0x40, 0x0A, 0x93, 0xFD, 0x32, 0xA0, 0x00, 0x21, 0x12, 0x04, 0x32, 0xEB, 0x00, 0x7B, 0x16, 0xF4, 0x32, 0x3D, 0x01, 0x57, 0xCB, 0x0C, 0x21, 0x38, 0x18, 0x9D, 0x32, 0x48, 0x01, 0xFC, 0x40, 0x03, 0x21, 0x38, 0x54, 0x01, 0x32, 0x36, 0x01, 0x46, 0x46, 0x0B, 0x31, 0x68, 0x8E, 0xD5, 0xEC, 0x31, 0x70, 0x58, 0xE2, 0x07, 0x31, 0x72, 0xB9, 0x2E, 0xF8, 0x32, 0x80, 0x00, 0x37, 0x15, 0x08, 0x32, 0x81, 0x00, 0x08, 0xEA, 0xF7, 0x32, 0x81, 0x00, 0xD2, 0x13, 0x01, 0x22, 0x8A, 0x00, 0xD3, 0x3E, 0x31, 0x74, 0x33, 0x1E, 0x04, 0x32, 0x98, 0x00, 0xFC, 0x0D, 0x0A, 0x31, 0x68, 0xBF, 0xE2, 0xF1, 0x32, 0x80, 0x00, 0xD1, 0x0A, 0xFE, 0x32, 0x80, 0x00, 0x8D, 0x0F, 0x16, 0x32, 0x80, 0x00, 0xB8, 0xD3, 0xEC, 0x32, 0x80, 0x00, 0x69, 0xFB, 0x01, 0x32, 0xD8, 0x02, 0x86, 0xA2, 0x06, 0x31, 0x42, 0xB6, 0x5A, 0xF9, 0x32, 0xF3, 0x00, 0x9B, 0xFF, 0xF7, 0x21, 0x73, 0xFB, 0xE5, 0x32, 0x80, 0x00, 0xE1, 0xE6, 0x12, 0x32, 0x00, 0x01, 0x43, 0xFC, 0xEB, 0x22, 0x00, 0x01, 0x00, 0xFF, 0x32, 0xC0, 0x00, 0xA6, 0xA9, 0x17, 0x21, 0x43, 0x8F, 0xEC, 0x32, 0x00, 0x01, 0x89, 0x70, 0xE5, 0x32, 0x00, 0x01, 0x02, 0xD0, 0x1A, 0x32, 0x80, 0x00, 0x4B, 0x7A, 0xEE, 0x21, 0x7D, 0x8A, 0xFD, 0x22, 0x80, 0x00, 0xAE, 0x03, 0x22, 0x80, 0x00, 0x85, 0x9C, 0x32, 0x80, 0x00, 0xA0, 0x3B, 0x14, 0x32, 0xE4, 0x00, 0xFE, 0x40, 0xFD, 0x31, 0x24, 0x5E, 0x26, 0xF3, 0x12, 0xC1, 0x00, 0x25, 0x31, 0x37, 0x13, 0xD5, 0x0C, 0x12, 0x80, 0x00, 0x47, 0x22, 0x80, 0x00, 0x90, 0x00, 0x32, 0x86, 0x00, 0x9B, 0x3D, 0xE9, 0x32, 0x80, 0x00, 0x8A, 0xB3, 0x17, 0x32, 0xFA, 0x00, 0x49, 0x9B, 0xED, 0x32, 0x00, 0x01, 0xB7, 0x62, 0x12, 0x00, 0x00]),
        Some(vec![
            DataRun {lcn_length: 517248, lcn_offset: 0, run_type: RunType::Sparse},
            DataRun {lcn_length: 71, lcn_offset: 3961442, run_type: RunType::Standard},
            DataRun {lcn_length: 73, lcn_offset: 4132643, run_type: RunType::Standard},
            DataRun {lcn_length: 160, lcn_offset: 3772347, run_type: RunType::Standard},
            DataRun {lcn_length: 160, lcn_offset: 4226207, run_type: RunType::Standard},
            DataRun {lcn_length: 64, lcn_offset: 4067241, run_type: RunType::Standard},
            DataRun {lcn_length: 160, lcn_offset: 4334026, run_type: RunType::Standard},
            DataRun {lcn_length: 235, lcn_offset: 3553349, run_type: RunType::Standard},
            DataRun {lcn_length: 317, lcn_offset: 4391836, run_type: RunType::Standard},
            DataRun {lcn_length: 56, lcn_offset: 4366516, run_type: RunType::Standard},
            DataRun {lcn_length: 328, lcn_offset: 4579760, run_type: RunType::Standard},
            DataRun {lcn_length: 56, lcn_offset: 4580100, run_type: RunType::Standard},
            DataRun {lcn_length: 310, lcn_offset: 5318986, run_type: RunType::Standard},
            DataRun {lcn_length: 104, lcn_offset: 4062936, run_type: RunType::Standard},
            DataRun {lcn_length: 112, lcn_offset: 4579632, run_type: RunType::Standard},
            DataRun {lcn_length: 114, lcn_offset: 4067305, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 4597024, run_type: RunType::Standard},
            DataRun {lcn_length: 129, lcn_offset: 4067112, run_type: RunType::Standard},
            DataRun {lcn_length: 129, lcn_offset: 4137722, run_type: RunType::Standard},
            DataRun {lcn_length: 138, lcn_offset: 4153805, run_type: RunType::Standard},
            DataRun {lcn_length: 116, lcn_offset: 4423680, run_type: RunType::Standard},
            DataRun {lcn_length: 152, lcn_offset: 5082620, run_type: RunType::Standard},
            DataRun {lcn_length: 104, lcn_offset: 4157627, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 4029324, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 5475097, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 4218577, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 4348474, run_type: RunType::Standard},
            DataRun {lcn_length: 728, lcn_offset: 4783296, run_type: RunType::Standard},
            DataRun {lcn_length: 66, lcn_offset: 4347766, run_type: RunType::Standard},
            DataRun {lcn_length: 243, lcn_offset: 3823377, run_type: RunType::Standard},
            DataRun {lcn_length: 115, lcn_offset: 3816716, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 5055469, run_type: RunType::Standard},
            DataRun {lcn_length: 256, lcn_offset: 3743792, run_type: RunType::Standard},
            DataRun {lcn_length: 256, lcn_offset: 3743536, run_type: RunType::Standard},
            DataRun {lcn_length: 192, lcn_offset: 5294294, run_type: RunType::Standard},
            DataRun {lcn_length: 67, lcn_offset: 5289317, run_type: RunType::Standard},
            DataRun {lcn_length: 256, lcn_offset: 3548654, run_type: RunType::Standard},
            DataRun {lcn_length: 256, lcn_offset: 5305840, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 4157499, run_type: RunType::Standard},
            DataRun {lcn_length: 125, lcn_offset: 4156869, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 4157811, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 4132344, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 5458328, run_type: RunType::Standard},
            DataRun {lcn_length: 228, lcn_offset: 5278358, run_type: RunType::Standard},
            DataRun {lcn_length: 36, lcn_offset: 4436212, run_type: RunType::Standard},
            DataRun {lcn_length: 193, lcn_offset: 4436249, run_type: RunType::Standard},
            DataRun {lcn_length: 55, lcn_offset: 5277228, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 5277299, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 5277443, run_type: RunType::Standard},
            DataRun {lcn_length: 134, lcn_offset: 3785886, run_type: RunType::Standard},
            DataRun {lcn_length: 128, lcn_offset: 5339176, run_type: RunType::Standard},
            DataRun {lcn_length: 250, lcn_offset: 4133745, run_type: RunType::Standard},
            DataRun {lcn_length: 256, lcn_offset: 5338664, run_type: RunType::Standard},
        ])
    );
}

#[test]
// if this test fails, most likely the datarun_offset is not being respected
fn test_data_runs_at_offset() {
    let sample = mft_sample_name("entry_data_run_at_offset");
    let mut parser = MftParser::from_path(sample).unwrap();

    for record in parser.iter_entries().take(1).filter_map(|a| a.ok()) {
        let attributes: Vec<MftAttribute> = record.iter_attributes().filter_map(Result::ok).collect();
        for attribute in attributes {
            if attribute.header.type_code == MftAttributeType::DATA {
                let data_runs = attribute.data.into_data_runs().unwrap();
                assert_eq!(data_runs.data_runs.len(), 53);
                assert_eq!(data_runs.data_runs[0].lcn_offset, 0);
                assert_eq!(data_runs.data_runs[0].lcn_length, 517248);
                assert_eq!(data_runs.data_runs[0].run_type, RunType::Sparse);
            }
        }
    }
}
