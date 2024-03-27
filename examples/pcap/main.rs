fn main() {
    println!("Generate the dissector output using `cargo run examples/pcap/pcap.pdl PcapFile > examples/pcap/pcap_dissector.lua`")
}

#[cfg(test)]
mod tests {
    use std::{io::BufWriter, path::PathBuf};

    use pdl_compiler::ast::SourceDatabase;
    use pdl_dissector::Args;

    #[test]
    fn golden_file() {
        let mut writer = BufWriter::new(Vec::new());
        let mut sources = SourceDatabase::new();
        pdl_dissector::run(
            Args {
                pdl_file: PathBuf::from(file!()).parent().unwrap().join("pcap.pdl"),
                target_packets: vec![String::from("PcapFile")],
            },
            &mut sources,
            &mut writer,
        )
        .unwrap();
        let dissector_output = writer.into_inner().unwrap();
        pretty_assertions::assert_str_eq!(
            include_str!("pcap_dissector.lua"),
            std::str::from_utf8(&dissector_output).unwrap(),
        );
    }
}
