
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

function create_bit_mask(offset, len, field_size)
    local result = 0
    for i=(field_size - offset - len),(field_size - offset - 1) do
        result = result + 2^i
    end
    return result
end

function get_ftype(bit_offset, bitlen)
    local effective_len = bit_offset % 8 + bitlen
    if effective_len <= 8 then
        return ftypes.UINT8, 8
    elseif effective_len <= 16 then
        return ftypes.UINT16, 16
    elseif effective_len <= 32 then
        return ftypes.UINT32, 32
    elseif effective_len <= 64 then
        return ftypes.UINT64, 64
    else
        return ftypes.BYTES, effective_len
    end
end
UnalignedProtoField = {
    new = function (name, abbr, bit_offset, bit_len)
        return ProtoField.new(name, abbr, ftypes.BYTES)
    end,
}
-- function new_proto_field(name, abbr, bit_offset, bit_len)
--     if bit_offset % 8 ~= 0 or bit_len % 8 ~= 0 then
--         -- Not byte aligned
--         local effective_len = bit_offset % 8 + bit_len
--         local ftype_len = math.ceil(effective_len / 8) * 8
--         local ftype = ftypes.BYTES
--         print("Created proto field " .. abbr .. " ftype=" .. ftype .. " mask=" .. create_bit_mask(bit_offset, bit_len, ftype_len))
--         return ProtoField.new(name, abbr, ftype, nil, nil, create_bit_mask(bit_offset, bit_len, ftype_len))
--     else
--         -- Byte aligned
--         return ProtoField.new(name, abbr, ftype)
--     end
-- end

-- End Utils section
local PacketType_enum = {}
local PacketType_enum_range = {}
local PacketType_enum_matcher = {}
PacketType_enum[0] = "Simple"
table.insert(PacketType_enum_range, {0, 0, "Simple"})
PacketType_enum_matcher["Simple"] = function(v) return v == 0 end
PacketType_enum[1] = "Enum"
table.insert(PacketType_enum_range, {1, 1, "Enum"})
PacketType_enum_matcher["Enum"] = function(v) return v == 1 end
PacketType_enum[2] = "Group"
table.insert(PacketType_enum_range, {2, 2, "Group"})
PacketType_enum_matcher["Group"] = function(v) return v == 2 end
PacketType_enum[3] = "Unaligned"
table.insert(PacketType_enum_range, {3, 3, "Unaligned"})
PacketType_enum_matcher["Unaligned"] = function(v) return v == 3 end
function TopLevel_protocol_fields(fields, path)
    local bit_offset = 0
    fields[path .. ".type"] = ProtoField.new("type", "type", ftypes.UINT8, PacketType_enum_range, base.RANGE_STRING)
    fields[path .. "._body_"] = ProtoField.new("_body_", "_body_", ftypes.BYTES)
    SimplePacket_protocol_fields(fields, path .. ".SimplePacket")
    EnumPacket_protocol_fields(fields, path .. ".EnumPacket")
    AskBrewHistory_protocol_fields(fields, path .. ".AskBrewHistory")
    UnalignedPacket_protocol_fields(fields, path .. ".UnalignedPacket")
end
-- Sequence { name: "TopLevel", fields: [Typedef { name: "type", abbr: "type", decl: Enum { name: "PacketType", values: [Value(TagValue { id: "Simple", loc: SourceRange { .. }, value: 0 }), Value(TagValue { id: "Enum", loc: SourceRange { .. }, value: 1 }), Value(TagValue { id: "Group", loc: SourceRange { .. }, value: 2 }), Value(TagValue { id: "Unaligned", loc: SourceRange { .. }, value: 3 })], len: BitLen(8) }, len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian }, Payload { name: "_body_", abbr: "_body_", ftype: FType(None), len: Bounded { referenced_fields: ["_body_:size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: ["SimplePacket", "EnumPacket", "AskBrewHistory", "UnalignedPacket"] }], children: [Sequence { name: "SimplePacket", fields: [Scalar { name: "scalar_value", abbr: "scalar_value", ftype: FType(Some(BitLen(64))), len: Bounded { referenced_fields: [], constant_factor: BitLen(64) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Simple" }] }, Sequence { name: "EnumPacket", fields: [Typedef { name: "addition", abbr: "addition", decl: Enum { name: "CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Enum" }] }, Sequence { name: "AskBrewHistory", fields: [Scalar { name: "pot", abbr: "pot", ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "offset", abbr: "offset", ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "limit", abbr: "limit", ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Group" }] }, Sequence { name: "UnalignedPacket", fields: [Scalar { name: "a", abbr: "a", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "b", abbr: "b", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "c", abbr: "c", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "d", abbr: "d", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Unaligned" }] }], constraints: [] }
function TopLevel_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Typedef { name: "type", abbr: "type", decl: Enum { name: "PacketType", values: [Value(TagValue { id: "Simple", loc: SourceRange { .. }, value: 0 }), Value(TagValue { id: "Enum", loc: SourceRange { .. }, value: 1 }), Value(TagValue { id: "Group", loc: SourceRange { .. }, value: 2 }), Value(TagValue { id: "Unaligned", loc: SourceRange { .. }, value: 3 })], len: BitLen(8) }, len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values["type"] = buffer(i, field_len):uint()
    if PacketType_enum[field_values["type"]] == nil then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values["type"])
    end
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".type"], buffer(i, field_len))
        i = i + field_len
    end
-- Payload { name: "_body_", abbr: "_body_", ftype: FType(None), len: Bounded { referenced_fields: ["_body_:size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: ["SimplePacket", "EnumPacket", "AskBrewHistory", "UnalignedPacket"] }
    local field_len = enforce_len_limit(sum_or_nil(0 / 8, field_values["_body_:size"]), buffer(i):len(), tree)
    field_values["_body_"] = buffer(i, field_len):raw()
    if field_len ~= 0 then
        if false then -- Just to make the following generated code more uniform
        --
        elseif SimplePacket_match_constraints(field_values) then
            local dissected_len = SimplePacket_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".SimplePacket")
            i = i + dissected_len
--
        elseif EnumPacket_match_constraints(field_values) then
            local dissected_len = EnumPacket_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".EnumPacket")
            i = i + dissected_len
--
        elseif AskBrewHistory_match_constraints(field_values) then
            local dissected_len = AskBrewHistory_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".AskBrewHistory")
            i = i + dissected_len
--
        elseif UnalignedPacket_match_constraints(field_values) then
            local dissected_len = UnalignedPacket_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".UnalignedPacket")
            i = i + dissected_len

        else
            tree:add_le(fields[path .. "._body_"], buffer(i, field_len))
            i = i + field_len
        end
    end
    return i
end
function SimplePacket_protocol_fields(fields, path)
    local bit_offset = 0
    fields[path .. ".scalar_value"] = ProtoField.new("scalar_value", "scalar_value", ftypes.UINT64, nil, nil, create_bit_mask(bit_offset, 64, 64))
    bit_offset = (bit_offset + 64) % 8
end
-- Sequence { name: "SimplePacket", fields: [Scalar { name: "scalar_value", abbr: "scalar_value", ftype: FType(Some(BitLen(64))), len: Bounded { referenced_fields: [], constant_factor: BitLen(64) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Simple" }] }
function SimplePacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Scalar { name: "scalar_value", abbr: "scalar_value", ftype: FType(Some(BitLen(64))), len: Bounded { referenced_fields: [], constant_factor: BitLen(64) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(64 / 8), buffer(i):len(), tree)
    field_values["scalar_value"] = buffer(i, math.ceil(i + field_len - math.floor(i))):uint64()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".scalar_value"], buffer(i, math.ceil(i + field_len - math.floor(i))))
        i = i + field_len
    end
    return i
end
function SimplePacket_match_constraints(field_values)
    return PacketType_enum_matcher["Simple"](field_values["type"])
end
local CoffeeAddition_enum = {}
local CoffeeAddition_enum_range = {}
local CoffeeAddition_enum_matcher = {}
CoffeeAddition_enum[0] = "Empty"
table.insert(CoffeeAddition_enum_range, {0, 0, "Empty"})
CoffeeAddition_enum_matcher["Empty"] = function(v) return v == 0 end
CoffeeAddition_enum[1] = "NonAlcoholic: Cream"
table.insert(CoffeeAddition_enum_range, {1, 1, "NonAlcoholic: Cream"})
CoffeeAddition_enum_matcher["Cream"] = function(v) return v == 1 end
CoffeeAddition_enum[2] = "NonAlcoholic: Vanilla"
table.insert(CoffeeAddition_enum_range, {2, 2, "NonAlcoholic: Vanilla"})
CoffeeAddition_enum_matcher["Vanilla"] = function(v) return v == 2 end
CoffeeAddition_enum[3] = "NonAlcoholic: Chocolate"
table.insert(CoffeeAddition_enum_range, {3, 3, "NonAlcoholic: Chocolate"})
CoffeeAddition_enum_matcher["Chocolate"] = function(v) return v == 3 end
CoffeeAddition_enum_matcher["NonAlcoholic"] = function(v) return 1 <= v and v <= 9 end
table.insert(CoffeeAddition_enum_range, {1, 9, "NonAlcoholic"})
CoffeeAddition_enum[10] = "Alcoholic: Whisky"
table.insert(CoffeeAddition_enum_range, {10, 10, "Alcoholic: Whisky"})
CoffeeAddition_enum_matcher["Whisky"] = function(v) return v == 10 end
CoffeeAddition_enum[11] = "Alcoholic: Rum"
table.insert(CoffeeAddition_enum_range, {11, 11, "Alcoholic: Rum"})
CoffeeAddition_enum_matcher["Rum"] = function(v) return v == 11 end
CoffeeAddition_enum[12] = "Alcoholic: Kahlua"
table.insert(CoffeeAddition_enum_range, {12, 12, "Alcoholic: Kahlua"})
CoffeeAddition_enum_matcher["Kahlua"] = function(v) return v == 12 end
CoffeeAddition_enum[13] = "Alcoholic: Aquavit"
table.insert(CoffeeAddition_enum_range, {13, 13, "Alcoholic: Aquavit"})
CoffeeAddition_enum_matcher["Aquavit"] = function(v) return v == 13 end
CoffeeAddition_enum_matcher["Alcoholic"] = function(v) return 10 <= v and v <= 19 end
table.insert(CoffeeAddition_enum_range, {10, 19, "Alcoholic"})
CoffeeAddition_enum_matcher["Custom"] = function(v) return 20 <= v and v <= 29 end
table.insert(CoffeeAddition_enum_range, {20, 29, "Custom"})
setmetatable(CoffeeAddition_enum, { __index = function () return "Other" end })
table.insert(CoffeeAddition_enum_range, {0, 2^1024, "Other"})
CoffeeAddition_enum_matcher["Other"] = function(v)
    for k,matcher in ipairs(CoffeeAddition_enum_matcher) do
        if k ~= "Other" then
            if matcher(v) then
                return false
            end
        end
    end
    return true
end
function EnumPacket_protocol_fields(fields, path)
    local bit_offset = 0
    fields[path .. ".addition"] = ProtoField.new("addition", "addition", ftypes.UINT8, CoffeeAddition_enum_range, base.RANGE_STRING)
end
-- Sequence { name: "EnumPacket", fields: [Typedef { name: "addition", abbr: "addition", decl: Enum { name: "CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Enum" }] }
function EnumPacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Typedef { name: "addition", abbr: "addition", decl: Enum { name: "CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values["addition"] = buffer(i, field_len):uint()
    if CoffeeAddition_enum[field_values["addition"]] == nil then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values["addition"])
    end
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".addition"], buffer(i, field_len))
        i = i + field_len
    end
    return i
end
function EnumPacket_match_constraints(field_values)
    return PacketType_enum_matcher["Enum"](field_values["type"])
end
function AskBrewHistory_protocol_fields(fields, path)
    local bit_offset = 0
    fields[path .. ".pot"] = ProtoField.new("pot", "pot", ftypes.UINT8, nil, nil, create_bit_mask(bit_offset, 8, 8))
    bit_offset = (bit_offset + 8) % 8
    fields[path .. ".offset"] = ProtoField.new("offset", "offset", ftypes.UINT8, nil, nil, create_bit_mask(bit_offset, 8, 8))
    bit_offset = (bit_offset + 8) % 8
    fields[path .. ".limit"] = ProtoField.new("limit", "limit", ftypes.UINT8, nil, nil, create_bit_mask(bit_offset, 8, 8))
    bit_offset = (bit_offset + 8) % 8
end
-- Sequence { name: "AskBrewHistory", fields: [Scalar { name: "pot", abbr: "pot", ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "offset", abbr: "offset", ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "limit", abbr: "limit", ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Group" }] }
function AskBrewHistory_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Scalar { name: "pot", abbr: "pot", ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values["pot"] = buffer(i, math.ceil(i + field_len - math.floor(i))):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".pot"], buffer(i, math.ceil(i + field_len - math.floor(i))))
        i = i + field_len
    end
-- Scalar { name: "offset", abbr: "offset", ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values["offset"] = buffer(i, math.ceil(i + field_len - math.floor(i))):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".offset"], buffer(i, math.ceil(i + field_len - math.floor(i))))
        i = i + field_len
    end
-- Scalar { name: "limit", abbr: "limit", ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values["limit"] = buffer(i, math.ceil(i + field_len - math.floor(i))):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".limit"], buffer(i, math.ceil(i + field_len - math.floor(i))))
        i = i + field_len
    end
    return i
end
function AskBrewHistory_match_constraints(field_values)
    return PacketType_enum_matcher["Group"](field_values["type"])
end
function UnalignedPacket_protocol_fields(fields, path)
    local bit_offset = 0
    fields[path .. ".a"] = ProtoField.new("a", "a", ftypes.UINT8, nil, nil, create_bit_mask(bit_offset, 3, 8))
    bit_offset = (bit_offset + 3) % 8
    fields[path .. ".b"] = ProtoField.new("b", "b", ftypes.UINT8, nil, nil, create_bit_mask(bit_offset, 3, 8))
    bit_offset = (bit_offset + 3) % 8
    fields[path .. ".c"] = ProtoField.new("c", "c", ftypes.UINT8, nil, nil, create_bit_mask(bit_offset, 3, 8))
    bit_offset = (bit_offset + 3) % 8
    fields[path .. ".d"] = ProtoField.new("d", "d", ftypes.UINT8, nil, nil, create_bit_mask(bit_offset, 3, 8))
    bit_offset = (bit_offset + 3) % 8
end
-- Sequence { name: "UnalignedPacket", fields: [Scalar { name: "a", abbr: "a", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "b", abbr: "b", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "c", abbr: "c", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "d", abbr: "d", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Unaligned" }] }
function UnalignedPacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Scalar { name: "a", abbr: "a", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(3 / 8), buffer(i):len(), tree)
    field_values["a"] = buffer(i, math.ceil(i + field_len - math.floor(i))):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".a"], buffer(i, math.ceil(i + field_len - math.floor(i))))
        i = i + field_len
    end
-- Scalar { name: "b", abbr: "b", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(3 / 8), buffer(i):len(), tree)
    field_values["b"] = buffer(i, math.ceil(i + field_len - math.floor(i))):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".b"], buffer(i, math.ceil(i + field_len - math.floor(i))))
        i = i + field_len
    end
-- Scalar { name: "c", abbr: "c", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(3 / 8), buffer(i):len(), tree)
    field_values["c"] = buffer(i, math.ceil(i + field_len - math.floor(i))):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".c"], buffer(i, math.ceil(i + field_len - math.floor(i))))
        i = i + field_len
    end
-- Scalar { name: "d", abbr: "d", ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(3 / 8), buffer(i):len(), tree)
    field_values["d"] = buffer(i, math.ceil(i + field_len - math.floor(i))):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".d"], buffer(i, math.ceil(i + field_len - math.floor(i))))
        i = i + field_len
    end
    return i
end
function UnalignedPacket_match_constraints(field_values)
    return PacketType_enum_matcher["Unaligned"](field_values["type"])
end
-- Protocol definition for "TopLevel"
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
