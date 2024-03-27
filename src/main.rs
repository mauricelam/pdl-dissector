use clap::Parser as _;
use codespan_reporting::term::termcolor::{ColorChoice, StandardStream};
use pdl_compiler::ast::SourceDatabase;

fn main() {
    let args = pdl_dissector::Args::parse();
    let mut sources = SourceDatabase::new();
    match pdl_dissector::run(args, &mut sources, &mut std::io::stdout()) {
        Ok(_) => {}
        Err(diag) => {
            let mut writer = StandardStream::stderr(ColorChoice::Always);
            diag.emit(&sources, &mut writer).unwrap();
        }
    }
}
