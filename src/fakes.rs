use mlua::Lua;

pub fn wireshark_lua() -> anyhow::Result<Lua> {
    let lua = Lua::new();
    lua.load(r#"function Proto() return {} end"#).exec()?;
    lua.load(r#"ProtoField = {}"#).exec()?;
    lua.load(r#"function ProtoField.new() return {} end"#)
        .exec()?;
    lua.load(r#"DissectorTable = { get = function() return { add = function() end } end }"#)
        .exec()?;
    lua.load(r#"
        function Tree()
            return {
                add = function() return Tree() end,
                add_le = function() return Tree() end,
                add_expert_info = function() end,
            }
        end
    "#).exec()?;
    lua.load(r#"
        function Tvb(bytes)
            local mt = {__call}
            local t = {
                bytes = bytes,
                len = function() return #bytes end,
                raw = function() return bytes end,
            }
            setmetatable(t, {__call = function() return t end})
            return t
        end
    "#).exec()?;
    lua.load(r#"function new_pinfo() return { cols = {} } end"#).exec()?;
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
    Ok(lua)
}
