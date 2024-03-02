use std::path::PathBuf;

use hex_literal::hex;
use pdl_dissector::Args;
use serde_json::json;

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
        "-Tjson",
        &format!("-Xlua_script:{}", file.path().to_string_lossy()),
    ]);
    let json_output = cmd.output()?.stdout;
    let json = serde_json::from_slice::<serde_json::Value>(&json_output)?;
    let top_level_vec: Vec<_> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            &item.as_object().unwrap()["_source"].as_object().unwrap()["layers"]
                .as_object()
                .unwrap()["toplevel"]
        })
        .collect();
    let expected = json!([
        {
            "type": "0",
            "scalar_value": u64::from_le_bytes(hex!("1234567812345678")).to_string(),
        },
        {
            "type": "1",
            "addition": "0",
        },
        {
            "type": "1",
            "addition": "2",
        },
        {
            "type": "1",
            "addition": "22",
        },
        {
            "type": "1",
            "addition": "68",
        }
    ]);
    assert_eq!(
        expected.as_array().unwrap().iter().collect::<Vec<_>>(),
        top_level_vec
    );
    Ok(())
}
