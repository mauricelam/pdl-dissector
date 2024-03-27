use codespan_reporting::{
    diagnostic::Diagnostic,
    term::{self, termcolor},
};
use pdl_compiler::ast::{FileId, SourceDatabase};

#[derive(Clone, Debug)]
pub struct Diagnostics(Vec<codespan_reporting::diagnostic::Diagnostic<FileId>>);

impl Diagnostics {
    pub fn emit(
        &self,
        sources: &SourceDatabase,
        writer: &mut dyn termcolor::WriteColor,
    ) -> Result<(), codespan_reporting::files::Error> {
        let config = term::Config::default();
        for d in self.0.iter() {
            term::emit(writer, &config, sources, d)?;
        }
        Ok(())
    }
}

impl std::fmt::Display for Diagnostics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self)
    }
}

impl std::error::Error for Diagnostics {}

impl From<pdl_compiler::analyzer::Diagnostics> for Diagnostics {
    fn from(diag: pdl_compiler::analyzer::Diagnostics) -> Self {
        Self(diag.diagnostics)
    }
}

impl From<codespan_reporting::diagnostic::Diagnostic<FileId>> for Diagnostics {
    fn from(diag: codespan_reporting::diagnostic::Diagnostic<FileId>) -> Self {
        Self(vec![diag])
    }
}

impl From<std::io::Error> for Diagnostics {
    fn from(value: std::io::Error) -> Self {
        Self(vec![Diagnostic::error().with_message(value.to_string())])
    }
}
