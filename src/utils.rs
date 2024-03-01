use pdl_compiler::ast::EndiannessValue;

use crate::{ByteLen, RuntimeLenInfo};

pub fn ftype_lua_expr(size: RuntimeLenInfo) -> &'static str {
    match size {
        RuntimeLenInfo::Bounded {
            constant_factor: ByteLen(1),
            referenced_fields: v,
        } if v.is_empty() => "ftypes.UINT8",
        RuntimeLenInfo::Bounded {
            constant_factor: ByteLen(2),
            referenced_fields: v,
        } if v.is_empty() => "ftypes.UINT16",
        RuntimeLenInfo::Bounded {
            constant_factor: ByteLen(3),
            referenced_fields: v,
        } if v.is_empty() => "ftypes.UINT24",
        RuntimeLenInfo::Bounded {
            constant_factor: ByteLen(4),
            referenced_fields: v,
        } if v.is_empty() => "ftypes.UINT32",
        RuntimeLenInfo::Bounded {
            constant_factor: ByteLen(8),
            referenced_fields: v,
        } if v.is_empty() => "ftypes.UINT64",
        RuntimeLenInfo::Bounded {
            constant_factor: ByteLen(_),
            referenced_fields: v,
        } if v.is_empty() => "ftypes.BYTES",
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
