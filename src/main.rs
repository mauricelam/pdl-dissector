use clap::Parser as _;

fn main() -> anyhow::Result<()> {
    let args = pdl_dissector::Args::parse();
    pdl_dissector::run(args, &mut std::io::stdout())
}
