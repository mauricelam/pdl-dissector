use pdl_compiler::{analyzer::ast::Size, ast::EndiannessValue};

use crate::RuntimeLenInfo;

// TODO: Change arg to RuntimeLenInfo?
pub fn ftype_lua_expr(size: Size) -> &'static str {
    match size {
        Size::Static(8) => "ftypes.UINT8",
        Size::Static(16) => "ftypes.UINT16",
        Size::Static(24) => "ftypes.UINT24",
        Size::Static(32) => "ftypes.UINT32",
        Size::Static(64) => "ftypes.UINT64",
        Size::Static(l) if l % 8 == 0 => "ftypes.BYTES",
        _ => "ftypes.BYTES",
    }
}

pub fn buffer_value_lua_function(endian: EndiannessValue, len: &RuntimeLenInfo) -> String {
    match len {
        RuntimeLenInfo::Bounded {
            referenced_fields: v,
            constant_factor,
        } if v.is_empty() => {
            let lua_func = match endian {
                EndiannessValue::LittleEndian if constant_factor.0 > 4 => "uint64",
                EndiannessValue::LittleEndian => "uint",
                EndiannessValue::BigEndian if constant_factor.0 > 4 => "le_uint64",
                EndiannessValue::BigEndian => "le_uint",
            };
            format!("{lua_func}()")
        }
        _ => "raw()".into(),
    }
}
