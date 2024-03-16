use pdl_compiler::ast::EndiannessValue;

use crate::indent_write::IoWriteExt;
use crate::RuntimeLenInfo;

pub fn buffer_value_lua_function(endian: EndiannessValue, len: &RuntimeLenInfo) -> String {
    match len {
        RuntimeLenInfo::Bounded {
            referenced_fields: v,
            constant_factor,
        } if v.is_empty() => {
            let lua_func = match endian {
                EndiannessValue::LittleEndian if constant_factor.0 > 32 => "uint64",
                EndiannessValue::LittleEndian => "le_uint",
                EndiannessValue::BigEndian if constant_factor.0 > 32 => "le_uint64",
                EndiannessValue::BigEndian => "uint",
            };
            format!("{lua_func}()")
        }
        _ => "raw()".into(),
    }
}

pub fn lua_if_then_else<W: std::io::Write + Sized>(
    mut writer: W,
    iter: impl IntoIterator<
        Item = (
            String,
            impl FnMut(&mut dyn std::io::Write) -> std::io::Result<()>,
        ),
    >,
    else_branch: Option<impl FnMut(&mut dyn std::io::Write) -> std::io::Result<()>>,
) -> Result<(), std::io::Error> {
    let mut first = true;
    for (cond, mut writable) in iter {
        let if_or_else_if = if first { "if" } else { "elseif" };
        first = false;
        writeln!(writer, r#"{if_or_else_if} {cond} then"#)?;
        writable(&mut writer.indent())?;
    }
    if first {
        if let Some(mut else_body) = else_branch {
            else_body(&mut writer)?;
        }
    } else {
        if let Some(mut else_body) = else_branch {
            writeln!(writer, "else")?;
            else_body(&mut writer.indent())?;
        }
        writeln!(writer, "end")?;
    }
    Ok(())
}
