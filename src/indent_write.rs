pub trait IoWriteExt: std::io::Write + Sized {
    fn indent(&mut self) -> indent_write::io::IndentWriter<&mut Self>;
}

impl<W: std::io::Write> IoWriteExt for W {
    fn indent(&mut self) -> indent_write::io::IndentWriter<&mut Self> {
        indent_write::io::IndentWriter::new("    ", self)
    }
}

pub trait FmtWriteExt: std::fmt::Write + Sized {
    fn indent(&mut self) -> indent_write::fmt::IndentWriter<&mut Self>;
}

impl<W: std::fmt::Write> FmtWriteExt for W {
    fn indent(&mut self) -> indent_write::fmt::IndentWriter<&mut Self> {
        indent_write::fmt::IndentWriter::new("    ", self)
    }
}
