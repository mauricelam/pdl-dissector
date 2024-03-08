//! Basic fake / mock types to make sure the generated Lua code compiles.
//!
//! Currently these fakes are not functional – they cannot be used to test the behavior of the
//! callers, just whether the compilation was successful.

use mlua::{chunk, Lua};

pub fn wireshark_lua() -> anyhow::Result<Lua> {
    let lua = Lua::new();
    lua.load(chunk! {
        function Proto() return { fields = {} } end
        ProtoField = {}
        function ProtoField.new() return {} end
    })
    .exec()?;
    lua.load(r#"DissectorTable = { get = function() return { add = function() end } end }"#)
        .exec()?;
    lua.load(
        r#"
        function Tree()
            return {
                add = function() return Tree() end,
                add_le = function() return Tree() end,
                add_expert_info = function() end,
            }
        end
    "#,
    )
    .exec()?;
    lua.load(
        r#"
        function Tvb(bytes)
            local mt = {__call}
            local t = {
                bytes = bytes,
                len = function() return #bytes end,
                raw = function() return bytes end,
                uint64 = function() return 0 end,
                uint = function() return 0 end,
            }
            setmetatable(t, {__call = function() return t end})
            return t
        end
    "#,
    )
    .exec()?;
    lua.load(r#"function new_pinfo() return { cols = {} } end"#)
        .exec()?;
    lua.load(
        r#"ftypes = {
            BOOLEAN = {},
            CHAR = {},
            UINT8 = {},
            UINT16 = {},
            UINT24 = {},
            UINT32 = {},
            UINT64 = {},
            INT8 = {},
            INT16 = {},
            INT24 = {},
            INT32 = {},
            INT64 = {},
            FLOAT = {},
            DOUBLE = {},
            ABSOLUTE_TIME = {},
            RELATIVE_TIME = {},
            STRING = {},
            STRINGZ = {},
            UINT_STRING = {},
            ETHER = {},
            BYTES = {},
            UINT_BYTES = {},
            IPv4 = {},
            IPv6 = {},
            IPXNET = {},
            FRAMENUM = {},
            PCRE = {},
            GUID = {},
            OID = {},
            PROTOCOL = {},
            REL_OID = {},
            SYSTEM_ID = {},
            EUI64 = {},
            NONE = {},
        }"#,
    )
    .exec()?;
    lua.load(chunk! {
        base = {
            NONE = {}, DEC = {}, HEX = {}, OCT = {}, DEC_HEX = {}, HEX_DEC = {},
            RANGE_STRING = {}, UNIT_STRING = {},
        }
    })
    .exec()?;
    Ok(lua)
}
