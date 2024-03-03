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

    fn get_field<'a>(proto: &'a pdml::Proto, name: &str) -> Option<&'a str> {
        proto
            .field
            .iter()
            .find(|field| field.name == name)
            .and_then(|field| field.showname.as_deref())
    }
    fn get_fields(proto: &pdml::Proto) -> Vec<&str> {
        proto
            .field
            .iter()
            .filter_map(|field| field.showname.as_deref())
            .collect()
    }
    assert_eq!(
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
        ],
        top_levels
            .iter()
            .map(|tag| get_fields(tag))
            .collect::<Vec<_>>()
    );
    Ok(())
}
