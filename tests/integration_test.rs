use std::io::{BufRead, Write};
use std::path::PathBuf;

use hex_literal::hex;
use pdl_compiler::ast::SourceDatabase;
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
    let mut sources = SourceDatabase::new();
    pdl_dissector::run(args, &mut sources, &mut file)?;
    writeln!(
        file,
        r#"DissectorTable.get("tcp.port"):add(8000, TopLevel_protocol)"#
    )?;

    let tshark_version = std::process::Command::new("tshark")
        .arg("--version")
        .output()?
        .stdout
        .lines()
        .next()
        .unwrap()?;

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
        fn push_field(v: &mut Vec<String>, field: &pdml::Field, prefix: String) {
            if let Some(string) = field.showname.as_deref() {
                v.push(format!("{prefix}[{name}] {string}", name = field.name));
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
                "[TopLevel.type] type: Simple (0)",
                "[_ws.lua.text] SimplePacket",
                &format!(
                    "  [TopLevel.SimplePacket.scalar_value] scalar_value: {}",
                    u64::from_le_bytes(hex!("1234567812345678"))
                ),
            ],
            vec![
                "[TopLevel.type] type: Enum (1)",
                "[_ws.lua.text] EnumPacket",
                "  [TopLevel.EnumPacket.addition] addition: Empty (0)",
            ],
            vec![
                "[TopLevel.type] type: Enum (1)",
                "[_ws.lua.text] EnumPacket",
                "  [TopLevel.EnumPacket.addition] addition: NonAlcoholic: Vanilla (2)",
            ],
            vec![
                "[TopLevel.type] type: Enum (1)",
                "[_ws.lua.text] EnumPacket",
                "  [TopLevel.EnumPacket.addition] addition: Custom (22)",
            ],
            if tshark_version.contains("TShark (Wireshark) 4.") {
                vec![
                    "[TopLevel.type] type: Enum (1)",
                    "[_ws.lua.text] EnumPacket",
                    "  [TopLevel.EnumPacket.addition] addition: Other (68)",
                ]
            } else {
                vec![
                    "[TopLevel.type] type: Enum (1)",
                    "[_ws.lua.text] EnumPacket",
                    "  [TopLevel.EnumPacket.addition] addition: Unknown (68)",
                ]
            },
            vec![
                "[TopLevel.type] type: Group (2)",
                "[_ws.lua.text] Group_AskBrewHistory",
                "  [TopLevel.Group_AskBrewHistory.pot] pot: 1",
                "  [TopLevel.Group_AskBrewHistory.offset] offset: 2",
                "  [TopLevel.Group_AskBrewHistory.limit] limit: 3",
            ],
            vec![
                "[TopLevel.type] type: Unaligned (3)",
                "[_ws.lua.text] UnalignedPacket",
                "  [TopLevel.UnalignedPacket.a] 001. .... = a: 1",
                "  [TopLevel.UnalignedPacket.b] ...0 0000 010. .... = b: 2",
                "  [TopLevel.UnalignedPacket.c] ...0 11.. = c: 3",
                "  [TopLevel.UnalignedPacket.d] .... ..10 0... .... = d: 4",
                "  [TopLevel.UnalignedPacket.e] .101 .... = e: 5",
                "[_ws.expert] Expert Info (Warning/Malformed): Error: 4 undissected bits remaining",
                "  [_ws.lua.proto.warning] Error: 4 undissected bits remaining",
                "  [_ws.expert.message] Message: Error: 4 undissected bits remaining",
                "  [_ws.expert.severity] Severity level: Warning",
                "  [_ws.expert.group] Group: Malformed",
            ],
            vec![
                "[TopLevel.type] type: Checksum (4)",
                "[_ws.lua.text] ChecksumPacket",
                "  [TopLevel.ChecksumPacket.a] a: 1",
                "  [TopLevel.ChecksumPacket.b] b: 2",
                "  [TopLevel.ChecksumPacket.crc] crc: 0x3412"
            ],
            vec![
                "[TopLevel.type] type: Array (5)",
                "[_ws.lua.text] Array_Brew",
                "  [TopLevel.Array_Brew.pots] pots: 18",
                "  [TopLevel.Array_Brew.pots] pots: 52",
                "  [TopLevel.Array_Brew.additions] additions: Alcoholic: Whisky (10)",
                "  [TopLevel.Array_Brew.additions] additions: NonAlcoholic: Cream (1)",
                "  [TopLevel.Array_Brew.extra_additions] extra_additions: Custom (22)",
                "  [TopLevel.Array_Brew.extra_additions] extra_additions: Custom (28)",
            ],
            vec![
                "[TopLevel.type] type: Array (5)",
                "[_ws.lua.text] Array_Brew",
                "  [TopLevel.Array_Brew.pots] pots: 18",
                "  [TopLevel.Array_Brew.pots] pots: 52",
                "  [TopLevel.Array_Brew.additions] additions: Alcoholic: Whisky (10)",
                "  [_ws.expert] Expert Info (Warning/Malformed): Error: Expected 2 `additions` items but only found 1",
                "    [_ws.lua.proto.warning] Error: Expected 2 `additions` items but only found 1",
                "    [_ws.expert.message] Message: Error: Expected 2 `additions` items but only found 1",
                "    [_ws.expert.severity] Severity level: Warning",
                "    [_ws.expert.group] Group: Malformed",
            ],
            vec![
                "[TopLevel.type] type: GroupConstraint (6)",
                "[_ws.lua.text] GroupConstraint_Packet",
                "  [_ws.lua.text] s",
                "    [TopLevel.GroupConstraint_Packet._fixed_0] Fixed value: 42",
            ],
            vec![
                "[TopLevel.type] type: GroupConstraint (6)",
                "[_ws.lua.text] GroupConstraint_Packet",
                "  [_ws.lua.text] s",
                "    [TopLevel.GroupConstraint_Packet._fixed_0] Fixed value: 0",
                "      [_ws.expert] Expert Info (Warning/Malformed): Error: Expected `value == 42` where value=0",
                "        [_ws.lua.proto.warning] Error: Expected `value == 42` where value=0",
                "        [_ws.expert.message] Message: Error: Expected `value == 42` where value=0",
                "        [_ws.expert.severity] Severity level: Warning",
                "        [_ws.expert.group] Group: Malformed",
            ],
            vec![
                "[TopLevel.type] type: Size_Parent (7)",
                "[_ws.lua.text] Size_Parent",
                "  [TopLevel.Size_Parent._payload__size] 11.. .... = Size(Payload): 3",
                &format!(
                    "  [TopLevel.Size_Parent._payload_] ..00 0000 0100 0000 1000 0000 11.. .... = Payload: {}",
                    0x010203
                ),
                "[_ws.expert] Expert Info (Warning/Malformed): Error: 6 undissected bits remaining",
                "  [_ws.lua.proto.warning] Error: 6 undissected bits remaining",
                "  [_ws.expert.message] Message: Error: 6 undissected bits remaining",
                "  [_ws.expert.severity] Severity level: Warning",
                "  [_ws.expert.group] Group: Malformed",
            ],
            vec![
                "[TopLevel.type] type: Size_Array (8)",
                "[_ws.lua.text] Size_Brew",
                "  [TopLevel.Size_Brew.pot] pot: 18",
                "  [TopLevel.Size_Brew.additions_size] Size(additions): 2",
                "  [TopLevel.Size_Brew.additions] additions: Alcoholic: Rum (11)",
                "  [TopLevel.Size_Brew.additions] additions: Custom (24)",
                "[_ws.expert] Expert Info (Warning/Malformed): Error: 1 undissected bytes remaining",
                "  [_ws.lua.proto.warning] Error: 1 undissected bytes remaining",
                "  [_ws.expert.message] Message: Error: 1 undissected bytes remaining",
                "  [_ws.expert.severity] Severity level: Warning",
                "  [_ws.expert.group] Group: Malformed",
            ],
            vec![
                "[TopLevel.type] type: Size_Array (8)",
                "[_ws.lua.text] Size_Brew",
                "  [TopLevel.Size_Brew.pot] pot: 18",
                "  [TopLevel.Size_Brew.additions_size] Size(additions): 3",
                "  [_ws.expert] Expert Info (Warning/Malformed): Error: Size(additions) is greater than the number of remaining bytes",
                "    [_ws.lua.proto.warning] Error: Size(additions) is greater than the number of remaining bytes",
                "    [_ws.expert.message] Message: Error: Size(additions) is greater than the number of remaining bytes",
                "    [_ws.expert.severity] Severity level: Warning",
                "    [_ws.expert.group] Group: Malformed",
                "  [TopLevel.Size_Brew.additions] additions: Alcoholic: Rum (11)",
                "  [TopLevel.Size_Brew.additions] additions: Custom (24)",
            ],
            vec![
                "[TopLevel.type] type: InheritanceWithoutConstraint (9)",
                "[_ws.lua.text] AbstractParent",
                "  [_ws.lua.text] ChildWithoutConstraints",
                "    [TopLevel.AbstractParent.ChildWithoutConstraints.field] field: 136",
            ],
            vec![
                "[TopLevel.type] type: PayloadWithSizeModifier (10)",
                "[_ws.lua.text] PayloadWithSizeModifier",
                "  [TopLevel.PayloadWithSizeModifier.additions_size] Size(additions): 1",
                "  [TopLevel.PayloadWithSizeModifier.additions] additions: NonAlcoholic: Cream (1)",
                "  [TopLevel.PayloadWithSizeModifier.additions] additions: Alcoholic: Whisky (10)",
                "  [TopLevel.PayloadWithSizeModifier.additions] additions: Custom (20)",
                "[_ws.expert] Expert Info (Warning/Malformed): Error: 1 undissected bytes remaining",
                "  [_ws.lua.proto.warning] Error: 1 undissected bytes remaining",
                "  [_ws.expert.message] Message: Error: 1 undissected bytes remaining",
                "  [_ws.expert.severity] Severity level: Warning",
                "  [_ws.expert.group] Group: Malformed",
            ],
            vec![
                "[TopLevel.type] type: Fixed (11)",
                "[_ws.lua.text] Fixed_Teapot",
                "  [TopLevel.Fixed_Teapot._fixed_0] Fixed value: 42",
                "  [TopLevel.Fixed_Teapot._fixed_1] Fixed value: Empty: 0",
            ],
            vec![
                "[TopLevel.type] type: Fixed (11)",
                "[_ws.lua.text] Fixed_Teapot",
                "  [TopLevel.Fixed_Teapot._fixed_0] Fixed value: 80",
                "    [_ws.expert] Expert Info (Warning/Malformed): Error: Expected `value == 42` where value=80",
                "      [_ws.lua.proto.warning] Error: Expected `value == 42` where value=80",
                "      [_ws.expert.message] Message: Error: Expected `value == 42` where value=80",
                "      [_ws.expert.severity] Severity level: Warning",
                "      [_ws.expert.group] Group: Malformed",
                "  [TopLevel.Fixed_Teapot._fixed_1] Fixed value: Empty: 0",
            ],
            vec![
                "[TopLevel.type] type: Fixed (11)",
                "[_ws.lua.text] Fixed_Teapot",
                "  [TopLevel.Fixed_Teapot._fixed_0] Fixed value: 42",
                "  [TopLevel.Fixed_Teapot._fixed_1] Fixed value: Empty: 1",
                "    [_ws.expert] Expert Info (Warning/Malformed): Error: Expected `Enum_CoffeeAddition_enum:match(\"Empty\", value)` where value=1",
                "      [_ws.lua.proto.warning] Error: Expected `Enum_CoffeeAddition_enum:match(\"Empty\", value)` where value=1",
                "      [_ws.expert.message] Message: Error: Expected `Enum_CoffeeAddition_enum:match(\"Empty\", value)` where value=1",
                "      [_ws.expert.severity] Severity level: Warning",
                "      [_ws.expert.group] Group: Malformed",
            ],
            vec! [
                "[TopLevel.type] type: Padding (12)",
                "[_ws.lua.text] Padding_PaddedCoffee",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): NonAlcoholic: Cream (1)",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): Custom (20)",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): Empty (0)",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): Empty (0)",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): Empty (0)",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): Empty (0)",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): Empty (0)",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): Empty (0)",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): Empty (0)",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): Empty (0)",
            ],
            vec![
                "[TopLevel.type] type: Padding (12)",
                "[_ws.lua.text] Padding_PaddedCoffee",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): NonAlcoholic: Cream (1)",
                "  [TopLevel.Padding_PaddedCoffee.additions] additions (Padded): Custom (20)",
                "  [_ws.expert] Expert Info (Warning/Malformed): Error: Expected a minimum of 10 octets in field `additions (Padded)`",
                "    [_ws.lua.proto.warning] Error: Expected a minimum of 10 octets in field `additions (Padded)`",
                "    [_ws.expert.message] Message: Error: Expected a minimum of 10 octets in field `additions (Padded)`",
                "    [_ws.expert.severity] Severity level: Warning",
                "    [_ws.expert.group] Group: Malformed",
            ],
            vec![
                "[TopLevel.type] type: Reserved (13)",
                "[_ws.lua.text] Reserved_DeloreanCoffee",
                "  [TopLevel.Reserved_DeloreanCoffee._reserved_0] 0000 0001 0000 0010 0000 .... = Reserved: 4128",
                "[_ws.expert] Expert Info (Warning/Malformed): Error: 4 undissected bits remaining",
                "  [_ws.lua.proto.warning] Error: 4 undissected bits remaining",
                "  [_ws.expert.message] Message: Error: 4 undissected bits remaining",
                "  [_ws.expert.severity] Severity level: Warning",
                "  [_ws.expert.group] Group: Malformed",
            ],
            vec![
                "[TopLevel.type] type: Optional (14)",
                "[_ws.lua.text] Optional_CoffeeWithAdditions",
                "  [TopLevel.Optional_CoffeeWithAdditions.want_sugar] 1... .... = want_sugar: 1",
                "  [TopLevel.Optional_CoffeeWithAdditions.want_cream] .1.. .... = want_cream: 1",
                "  [TopLevel.Optional_CoffeeWithAdditions.want_alcohol] ..1. .... = want_alcohol: 1",
                "  [TopLevel.Optional_CoffeeWithAdditions._reserved_0] ...0 0000 = Reserved: 0",
                &format!("  [TopLevel.Optional_CoffeeWithAdditions.sugar] sugar: {}", 0x3344),
                "  [_ws.lua.text] cream",
                "    [TopLevel.Optional_CoffeeWithAdditions.fat_percentage] fat_percentage: 2",
                "  [TopLevel.Optional_CoffeeWithAdditions.alcohol] alcohol: WHISKY (0)",
            ],
            vec![
                "[TopLevel.type] type: Optional (14)",
                "[_ws.lua.text] Optional_CoffeeWithAdditions",
                "  [TopLevel.Optional_CoffeeWithAdditions.want_sugar] 0... .... = want_sugar: 0",
                "  [TopLevel.Optional_CoffeeWithAdditions.want_cream] .0.. .... = want_cream: 0",
                "  [TopLevel.Optional_CoffeeWithAdditions.want_alcohol] ..1. .... = want_alcohol: 1",
                "  [TopLevel.Optional_CoffeeWithAdditions._reserved_0] ...0 0000 = Reserved: 0",
                "  [TopLevel.Optional_CoffeeWithAdditions.alcohol] alcohol: WHISKY (0)",
            ],
            vec![
                "[TopLevel.type] type: Optional (14)",
                "[_ws.lua.text] Optional_CoffeeWithAdditions",
                "  [TopLevel.Optional_CoffeeWithAdditions.want_sugar] 1... .... = want_sugar: 1",
                "  [TopLevel.Optional_CoffeeWithAdditions.want_cream] .0.. .... = want_cream: 0",
                "  [TopLevel.Optional_CoffeeWithAdditions.want_alcohol] ..1. .... = want_alcohol: 1",
                "  [TopLevel.Optional_CoffeeWithAdditions._reserved_0] ...0 0000 = Reserved: 0",
                &format!("  [TopLevel.Optional_CoffeeWithAdditions.sugar] sugar: {}", 0x3344),
                "  [TopLevel.Optional_CoffeeWithAdditions.alcohol] alcohol: COGNAC (1)",
            ],
            vec![
                "[TopLevel.type] type: UnalignedEnum (15)",
                "[_ws.lua.text] UnalignedEnum_packet",
                "  [TopLevel.UnalignedEnum_packet.enum1] 001. .... = enum1: A (1)",
                "  [TopLevel.UnalignedEnum_packet.enum2] ...0 10.. = enum2: B (2)",
                "  [TopLevel.UnalignedEnum_packet.enum3] .... ..01 1... .... = enum3: C (3)",
                "[_ws.expert] Expert Info (Warning/Malformed): Error: 7 undissected bits remaining",
                "  [_ws.lua.proto.warning] Error: 7 undissected bits remaining",
                "  [_ws.expert.message] Message: Error: 7 undissected bits remaining",
                "  [_ws.expert.severity] Severity level: Warning",
                "  [_ws.expert.group] Group: Malformed",
            ],
        ],
        top_levels
            .iter()
            .map(|tag| get_fields(tag))
            .collect::<Vec<_>>()
    );
    Ok(())
}
