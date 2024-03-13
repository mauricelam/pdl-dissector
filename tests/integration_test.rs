use std::path::PathBuf;

use hex_literal::hex;
use pdl_dissector::{
    pdml::{self, Pdml},
    Args,
};

#[test]
fn golden_test() -> anyhow::Result<()> {
    let mut file = tempfile::NamedTempFile::new()?;
    let args = Args {
        pdl_file: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_le.pdl"),
        target_packets: vec![String::from("TopLevel")],
    };
    pdl_dissector::run(args, &mut file)?;

    let mut cmd = std::process::Command::new("tshark");
    cmd.args([
        "-r",
        "tools/payload.pcap",
        "-Tpdml",
        &format!("-Xlua_script:{}", file.path().to_string_lossy()),
    ]);
    let pdml_output = cmd.output()?.stdout;
    let pdml: Pdml = quick_xml::de::from_str(std::str::from_utf8(&pdml_output)?)?;
    let top_levels: Vec<&pdml::Proto> = pdml
        .packet
        .iter()
        .map(|packet| {
            packet
                .proto
                .iter()
                .find(|proto| proto.name == "toplevel")
                .unwrap()
        })
        .collect();

    fn get_fields(proto: &pdml::Proto) -> Vec<String> {
        let mut v = vec![];
        fn push_field<'f>(v: &mut Vec<String>, field: &'f pdml::Field, prefix: String) {
            if let Some(string) = field.showname.as_deref() {
                v.push(format!("{prefix}{string}"));
            }
            for child_field in &field.field {
                push_field(v, child_field, format!("  {prefix}"));
            }
        }
        for field in &proto.field {
            push_field(&mut v, field, String::new());
        }
        v
    }
    pretty_assertions::assert_eq!(
        vec![
            vec![
                "type: Simple (0)",
                &format!(
                    "scalar_value: {}",
                    u64::from_le_bytes(hex!("1234567812345678"))
                ),
            ],
            vec!["type: Enum (1)", "addition: Empty (0)"],
            vec!["type: Enum (1)", "addition: NonAlcoholic: Vanilla (2)"],
            vec!["type: Enum (1)", "addition: Custom (22)"],
            vec!["type: Enum (1)", "addition: Other (68)"],
            vec!["type: Group (2)", "pot: 1", "offset: 2", "limit: 3"],
            vec![
                "type: Unaligned (3)",
                "001. .... = a: 1",
                "...0 0000 010. .... = b: 2",
                "...0 11.. = c: 3",
                ".... ..10 0... .... = d: 4",
                ".101 .... = e: 5"
            ],
            vec!["type: Checksum (4)", "a: 1", "b: 2", "crc: 0x3412",],
            vec![
                "type: Array (5)",
                "pots: 18",
                "pots: 52",
                "additions: Alcoholic: Whisky (10)",
                "additions: NonAlcoholic: Cream (1)",
                "extra_additions: Custom (22)",
                "extra_additions: Custom (28)",
            ],
            vec![
                "type: GroupConstraint (6)",
                "s",
                "  Fixed value: 42",
            ],
            vec![
                "type: GroupConstraint (6)",
                "s",
                "  Fixed value: 0",
                "    Expert Info (Warning/Malformed): Error: Expected `value == 42`",
                "      Error: Expected `value == 42`",
                "      Message: Error: Expected `value == 42`",
                "      Severity level: Warning",
                "      Group: Malformed",
            ],
        ],
        top_levels
            .iter()
            .map(|tag| get_fields(tag))
            .collect::<Vec<_>>()
    );
    Ok(())
}
