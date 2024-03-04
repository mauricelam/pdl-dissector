use pdl_compiler::ast::EndiannessValue;

use crate::RuntimeLenInfo;

pub fn buffer_value_lua_function(endian: EndiannessValue, len: &RuntimeLenInfo) -> String {
    match len {
        RuntimeLenInfo::Bounded {
            referenced_fields: v,
            constant_factor,
        } if v.is_empty() => {
            let lua_func = match endian {
                EndiannessValue::LittleEndian if constant_factor.0 > 32 => "uint64",
                EndiannessValue::LittleEndian => "uint",
                EndiannessValue::BigEndian if constant_factor.0 > 32 => "le_uint64",
                EndiannessValue::BigEndian => "le_uint",
            };
            format!("{lua_func}()")
        }
        _ => "raw()".into(),
    }
}
