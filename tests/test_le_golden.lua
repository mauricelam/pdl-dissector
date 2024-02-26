local PacketType_enum = {}
PacketType_enum[0] = "Simple"
PacketType_enum[1] = "Enum"
function TopLevel_protocol_fields(fields, path)
    fields[path .. ".type"] = ProtoField.new("type", "type", ftypes.UINT8, PacketType_enum)
    fields[path .. "._body_"] = ProtoField.new("_body_", "_body_", ftypes.BYTES)
    SimplePacket_protocol_fields(fields, path .. ".SimplePacket")
    EnumPacket_protocol_fields(fields, path .. ".EnumPacket")
end
-- Sequence { name: "TopLevel", fields: [Typedef { name: "type", abbr: "type", decl: Enum { name: "PacketType", values: [Value(TagValue { id: "Simple", loc: SourceRange { .. }, value: 0 }), Value(TagValue { id: "Enum", loc: SourceRange { .. }, value: 1 })], len: 1 }, len: Bounded { referenced_fields: [], constant_factor: 1 }, endian: LittleEndian }, Scalar { name: "_body_", abbr: "_body_", ftype: "ftypes.BYTES", size: Unknown, len_bytes: Bounded { referenced_fields: ["_body_:size"], constant_factor: 0 }, endian: LittleEndian, validate_expr: None }], children: [Sequence { name: "SimplePacket", fields: [Scalar { name: "scalar_value", abbr: "scalar_value", ftype: "ftypes.UINT8", size: Static(8), len_bytes: Bounded { referenced_fields: [], constant_factor: 1 }, endian: LittleEndian, validate_expr: None }], children: [] }, Sequence { name: "EnumPacket", fields: [Typedef { name: "addition", abbr: "addition", decl: Enum { name: "CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: 1 }, len: Bounded { referenced_fields: [], constant_factor: 1 }, endian: LittleEndian }], children: [] }] }
function TopLevel_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Typedef { name: "type", abbr: "type", decl: Enum { name: "PacketType", values: [Value(TagValue { id: "Simple", loc: SourceRange { .. }, value: 0 }), Value(TagValue { id: "Enum", loc: SourceRange { .. }, value: 1 })], len: 1 }, len: Bounded { referenced_fields: [], constant_factor: 1 }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(1), buffer(i):len(), tree)
    field_values["type"] = buffer(i, field_len):raw()
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".type"], buffer(i, field_len))
        i = i + field_len
    end
-- Scalar { name: "_body_", abbr: "_body_", ftype: "ftypes.BYTES", size: Unknown, len_bytes: Bounded { referenced_fields: ["_body_:size"], constant_factor: 0 }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(0, field_values["_body_:size"]), buffer(i):len(), tree)
    field_values["_body_"] = buffer(i, field_len):raw()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. "._body_"], buffer(i, field_len))
        i = i + field_len
    end
    return i
end
function SimplePacket_protocol_fields(fields, path)
    fields[path .. ".scalar_value"] = ProtoField.new("scalar_value", "scalar_value", ftypes.UINT8)
end
-- Sequence { name: "SimplePacket", fields: [Scalar { name: "scalar_value", abbr: "scalar_value", ftype: "ftypes.UINT8", size: Static(8), len_bytes: Bounded { referenced_fields: [], constant_factor: 1 }, endian: LittleEndian, validate_expr: None }], children: [] }
function SimplePacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Scalar { name: "scalar_value", abbr: "scalar_value", ftype: "ftypes.UINT8", size: Static(8), len_bytes: Bounded { referenced_fields: [], constant_factor: 1 }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(1), buffer(i):len(), tree)
    field_values["scalar_value"] = buffer(i, field_len):raw()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".scalar_value"], buffer(i, field_len))
        i = i + field_len
    end
    return i
end
local CoffeeAddition_enum = {}
CoffeeAddition_enum[0] = "Empty"
CoffeeAddition_enum[1] = "NonAlcoholic: Cream"
CoffeeAddition_enum[2] = "NonAlcoholic: Vanilla"
CoffeeAddition_enum[3] = "NonAlcoholic: Chocolate"
CoffeeAddition_enum[10] = "Alcoholic: Whisky"
CoffeeAddition_enum[11] = "Alcoholic: Rum"
CoffeeAddition_enum[12] = "Alcoholic: Kahlua"
CoffeeAddition_enum[13] = "Alcoholic: Aquavit"
setmetatable(CoffeeAddition_enum, { __index = function () return "Other" end })
function EnumPacket_protocol_fields(fields, path)
    fields[path .. ".addition"] = ProtoField.new("addition", "addition", ftypes.UINT8, CoffeeAddition_enum)
end
-- Sequence { name: "EnumPacket", fields: [Typedef { name: "addition", abbr: "addition", decl: Enum { name: "CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: 1 }, len: Bounded { referenced_fields: [], constant_factor: 1 }, endian: LittleEndian }], children: [] }
function EnumPacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Typedef { name: "addition", abbr: "addition", decl: Enum { name: "CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: 1 }, len: Bounded { referenced_fields: [], constant_factor: 1 }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(1), buffer(i):len(), tree)
    field_values["addition"] = buffer(i, field_len):raw()
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".addition"], buffer(i, field_len))
        i = i + field_len
    end
    return i
end
TopLevel_protocol = Proto("TopLevel",  "TopLevel")
function TopLevel_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "TopLevel"
    local subtree = tree:add(TopLevel_protocol, buffer(), "TopLevel")
    TopLevel_dissect(buffer, pinfo, subtree, TopLevel_protocol.fields, "TopLevel")
end
TopLevel_protocol.fields = {}
TopLevel_protocol_fields(TopLevel_protocol.fields, "TopLevel")
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8000, TopLevel_protocol)
-- Utils section

function enforce_len_limit(num, limit, tree)
    if num == nil then
        return limit
    end
    if num > limit then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Expected " .. num .. " bytes, but only " .. limit .. " bytes remaining")
        return limit
    end
    return num
end

function sum_or_nil(...)
    local sum = 0
    local params = table.pack(...)
    for i=1,params.n do
        if params[i] == nil then
            return nil
        end
        sum = sum + params[i]
    end
    return sum
end

-- End Utils section
