-- Utils section
function enforce_len_limit(num, limit, tree)
    if num == nil then
        return limit
    end
    if num > limit then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR,
            "Expected " .. num .. " bytes, but only " .. limit .. " bytes remaining")
        return limit
    end
    return num
end

function sum_or_nil(...)
    local sum = 0
    local params = table.pack(...)
    for i = 1, params.n do
        if params[i] == nil then
            return nil
        end
        sum = sum + params[i]
    end
    return sum
end

function create_bit_mask(offset, len, field_size)
    local result = 0
    for i = (field_size - offset - len), (field_size - offset - 1) do
        result = result + 2 ^ i
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

AlignedProtoField = {}
function AlignedProtoField:new(o)
    local o = o or {
        name = nil,
        abbr = nil,
        ftype = nil,
        valuestring = nil,
        base = nil
    }
    o.field = ProtoField.new(o.name, o.abbr, o.ftype, o.valuestring, o.base)
    setmetatable(o, self)
    self.__index = self
    return o
end

-- function AlignedProtoField:dissect(tree, buffer)
--     field_values[self.abbr] = buffer(i, math.ceil(i + field_len - math.floor(i))):{buffer_value_function}
--     tree:add_le(fields[path .. "." .. self.name], buffer(i, math.ceil(i + field_len - math.floor(i))))
-- end

UnalignedProtoField = {}
function UnalignedProtoField:new(o)
    local o = o or {
        name = nil,
        abbr = nil,
        ftype = nil,
        bitoffset = nil,
        bitlen = nil -- optional
    }
    o.field = ProtoField.new(o.name, o.abbr, ftypes.BYTES)
    setmetatable(o, self)
    self.__index = self
    return o
end
-- Adds dissection info into `tree`, and returns (value, bit_length)
function UnalignedProtoField:dissect(tree, buffer, runtime_len)
    local bitlen = nil_coalesce(self.bitlen, runtime_len * 8)
    local numbytes = math.ceil((bitlen + self.bitoffset) / 8)
    local buf = buffer(0, numbytes)
    local value = buf:bitfield(self.bitoffset, bitlen)
    local label = string.rep(".", self.bitoffset) -- First add `offset` number of dots to represent insignificant bits
    for i = self.bitoffset, self.bitoffset + bitlen - 1 do
        label = label .. buf:bitfield(i, 1) -- Then add the binary value
    end
    -- Then add the remaining insignificant bits as dots
    label = label .. string.rep(".", numbytes * 8 - bitlen - self.bitoffset)
    label = format_bitstring(label) .. " = " .. self.name .. ": " .. value -- Print out the string label
    tree:add(buf, self.field, value, label):set_text(label)
    return value, bitlen
end

ProtoEnum = {}
function ProtoEnum:new()
    local o = {
        by_value = {},
        matchers = {}
    }
    setmetatable(o, self)
    self.__index = self
    return o
end

-- name: string
-- value: number | {min, max} (Range) | nil (Remaining)
function ProtoEnum:define(name, value)
    if value == nil then
        setmetatable(self.by_value, {
            __index = function()
                return name
            end
        })
        table.insert(self.matchers, {0, 2 ^ 1024, name})
    elseif type(value) == "table" then
        table.insert(self.matchers, {value[1], value[2], name})
    else
        self.by_value[value] = name
        table.insert(self.matchers, {value, value, name})
    end
end

function ProtoEnum:match(enum_name, value)
    for k,matcher in pairs(self.matchers) do
        if matcher[1] <= value and value <= matcher[2] then
            return matcher[3] == enum_name
        end
    end
    return false
end

-- Add a space every 4 characters in the string
-- Example: 0010010101 -> 0010 0101 01
function format_bitstring(input)
    return input:gsub("....", "%0 "):gsub(" $", "")
end

function nil_coalesce(a, b)
    if a ~= nil then
        return a
    else
        return b
    end
end

-- End Utils section
local PacketType_enum = ProtoEnum:new()
PacketType_enum:define("Simple", 0)
PacketType_enum:define("Enum", 1)
PacketType_enum:define("Group", 2)
PacketType_enum:define("Unaligned", 3)
PacketType_enum:define("Checksum", 4)
PacketType_enum:define("Array", 5)
PacketType_enum:define("GroupConstraint", 6)
PacketType_enum:define("Size_Parent", 7)
PacketType_enum:define("Size_Array", 8)
PacketType_enum:define("InheritanceWithoutConstraint", 9)
PacketType_enum:define("PayloadWithSizeModifier", 10)
PacketType_enum:define("Fixed", 11)
PacketType_enum:define("Padding", 12)
PacketType_enum:define("Reserved", 13)
function TopLevel_protocol_fields(fields, path)
    fields[path .. ".type"] = AlignedProtoField:new({
        name = "type",
        abbr = "type",
        ftype = ftypes.UINT8,
        valuestring = PacketType_enum.matchers,
        base = base.RANGE_STRING
    })
    fields[path .. "._body_"] = AlignedProtoField:new({
        name = "Body",
        abbr = path .. "._body_",
        ftype = ftypes.BYTES,
        bitlen = nil
    })
    SimplePacket_protocol_fields(fields, path .. ".SimplePacket")
    EnumPacket_protocol_fields(fields, path .. ".EnumPacket")
    Group_AskBrewHistory_protocol_fields(fields, path .. ".Group_AskBrewHistory")
    UnalignedPacket_protocol_fields(fields, path .. ".UnalignedPacket")
    ChecksumPacket_protocol_fields(fields, path .. ".ChecksumPacket")
    Array_Brew_protocol_fields(fields, path .. ".Array_Brew")
    GroupConstraint_Packet_protocol_fields(fields, path .. ".GroupConstraint_Packet")
    Size_Parent_protocol_fields(fields, path .. ".Size_Parent")
    Size_Brew_protocol_fields(fields, path .. ".Size_Brew")
    AbstractParent_protocol_fields(fields, path .. ".AbstractParent")
    PayloadWithSizeModifier_protocol_fields(fields, path .. ".PayloadWithSizeModifier")
    Fixed_Teapot_protocol_fields(fields, path .. ".Fixed_Teapot")
    Padding_PaddedCoffee_protocol_fields(fields, path .. ".Padding_PaddedCoffee")
    Reserved_DeloreanCoffee_protocol_fields(fields, path .. ".Reserved_DeloreanCoffee")
end
-- Sequence { name: "TopLevel", fields: [Typedef { name: "type", abbr: "type", decl: Enum { name: "PacketType", values: [Value(TagValue { id: "Simple", loc: SourceRange { .. }, value: 0 }), Value(TagValue { id: "Enum", loc: SourceRange { .. }, value: 1 }), Value(TagValue { id: "Group", loc: SourceRange { .. }, value: 2 }), Value(TagValue { id: "Unaligned", loc: SourceRange { .. }, value: 3 }), Value(TagValue { id: "Checksum", loc: SourceRange { .. }, value: 4 }), Value(TagValue { id: "Array", loc: SourceRange { .. }, value: 5 }), Value(TagValue { id: "GroupConstraint", loc: SourceRange { .. }, value: 6 }), Value(TagValue { id: "Size_Parent", loc: SourceRange { .. }, value: 7 }), Value(TagValue { id: "Size_Array", loc: SourceRange { .. }, value: 8 }), Value(TagValue { id: "InheritanceWithoutConstraint", loc: SourceRange { .. }, value: 9 }), Value(TagValue { id: "PayloadWithSizeModifier", loc: SourceRange { .. }, value: 10 }), Value(TagValue { id: "Fixed", loc: SourceRange { .. }, value: 11 }), Value(TagValue { id: "Padding", loc: SourceRange { .. }, value: 12 }), Value(TagValue { id: "Reserved", loc: SourceRange { .. }, value: 13 })], len: BitLen(8) }, endian: LittleEndian }, Payload { display_name: "Body", abbr: "_body_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_body__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: ["SimplePacket", "EnumPacket", "Group_AskBrewHistory", "UnalignedPacket", "ChecksumPacket", "Array_Brew", "GroupConstraint_Packet", "Size_Parent", "Size_Brew", "AbstractParent", "PayloadWithSizeModifier", "Fixed_Teapot", "Padding_PaddedCoffee", "Reserved_DeloreanCoffee"] }], children: [Sequence { name: "SimplePacket", fields: [Scalar { display_name: "scalar_value", abbr: "scalar_value", bit_offset: BitLen(0), ftype: FType(Some(BitLen(64))), len: Bounded { referenced_fields: [], constant_factor: BitLen(64) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Simple" }] }, Sequence { name: "EnumPacket", fields: [Typedef { name: "addition", abbr: "addition", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, endian: LittleEndian }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Enum" }] }, Sequence { name: "Group_AskBrewHistory", fields: [Scalar { display_name: "pot", abbr: "pot", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "offset", abbr: "offset", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "limit", abbr: "limit", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Group" }] }, Sequence { name: "UnalignedPacket", fields: [Scalar { display_name: "a", abbr: "a", bit_offset: BitLen(0), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "b", abbr: "b", bit_offset: BitLen(3), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "c", abbr: "c", bit_offset: BitLen(3), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "d", abbr: "d", bit_offset: BitLen(6), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "e", abbr: "e", bit_offset: BitLen(1), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Unaligned" }] }, Sequence { name: "ChecksumPacket", fields: [Scalar { display_name: "a", abbr: "a", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "b", abbr: "b", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Typedef { name: "crc", abbr: "crc", decl: Checksum { name: "CRC16", len: BitLen(16) }, endian: LittleEndian }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Checksum" }] }, Sequence { name: "Array_Brew", fields: [ScalarArray { display_name: "pots", abbr: "pots", ftype: FType(Some(BitLen(8))), bit_offset: BitLen(0), item_len: BitLen(8), count: Some(2), size_modifier: None, endian: LittleEndian, pad_to_size: None }, TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: Some(2), size_modifier: None, endian: LittleEndian, pad_to_size: None }, TypedefArray { name: "extra_additions", abbr: "extra_additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Array" }] }, Sequence { name: "GroupConstraint_Packet", fields: [Typedef { name: "s", abbr: "s", decl: Sequence { name: "GroupConstraint_Struct", fields: [Scalar { display_name: "Fixed value", abbr: "_fixed_101_4", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: Some("value == 42") }], children: [], constraints: [] }, endian: LittleEndian }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "GroupConstraint" }] }, Sequence { name: "Size_Parent", fields: [Scalar { display_name: "Size(Payload)", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(2))), len: Bounded { referenced_fields: [], constant_factor: BitLen(2) }, endian: LittleEndian, validate_expr: None }, Payload { display_name: "Payload", abbr: "_payload_", bit_offset: BitLen(2), ftype: FType(None), len: Bounded { referenced_fields: ["_payload__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Size_Parent" }] }, Sequence { name: "Size_Brew", fields: [Scalar { display_name: "pot", abbr: "pot", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "Size(additions)", abbr: "additions_size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Size_Array" }] }, Sequence { name: "AbstractParent", fields: [Payload { display_name: "Body", abbr: "_body_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_body__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: ["ChildWithoutConstraints"] }], children: [Sequence { name: "ChildWithoutConstraints", fields: [Scalar { display_name: "field", abbr: "field", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "InheritanceWithoutConstraint" }] }, Sequence { name: "PayloadWithSizeModifier", fields: [Scalar { display_name: "Size(additions)", abbr: "additions_size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: Some("+2"), endian: LittleEndian, pad_to_size: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "PayloadWithSizeModifier" }] }, Sequence { name: "Fixed_Teapot", fields: [Scalar { display_name: "Fixed value", abbr: "_fixed_152_2", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: Some("value == 42") }, Scalar { display_name: "Fixed value: Empty", abbr: "_fixed_0", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: Some("Enum_CoffeeAddition_enum:match(\"Empty\", value)") }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Fixed" }] }, Sequence { name: "Padding_PaddedCoffee", fields: [TypedefArray { name: "additions (Padded)", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: Some(10) }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Padding" }] }, Sequence { name: "Reserved_DeloreanCoffee", fields: [Scalar { display_name: "Reserved", abbr: "_reserved_0", bit_offset: BitLen(0), ftype: FType(Some(BitLen(20))), len: Bounded { referenced_fields: [], constant_factor: BitLen(20) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Reserved" }] }], constraints: [] }
function TopLevel_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Typedef { name: "type", abbr: "type", decl: Enum { name: "PacketType", values: [Value(TagValue { id: "Simple", loc: SourceRange { .. }, value: 0 }), Value(TagValue { id: "Enum", loc: SourceRange { .. }, value: 1 }), Value(TagValue { id: "Group", loc: SourceRange { .. }, value: 2 }), Value(TagValue { id: "Unaligned", loc: SourceRange { .. }, value: 3 }), Value(TagValue { id: "Checksum", loc: SourceRange { .. }, value: 4 }), Value(TagValue { id: "Array", loc: SourceRange { .. }, value: 5 }), Value(TagValue { id: "GroupConstraint", loc: SourceRange { .. }, value: 6 }), Value(TagValue { id: "Size_Parent", loc: SourceRange { .. }, value: 7 }), Value(TagValue { id: "Size_Array", loc: SourceRange { .. }, value: 8 }), Value(TagValue { id: "InheritanceWithoutConstraint", loc: SourceRange { .. }, value: 9 }), Value(TagValue { id: "PayloadWithSizeModifier", loc: SourceRange { .. }, value: 10 }), Value(TagValue { id: "Fixed", loc: SourceRange { .. }, value: 11 }), Value(TagValue { id: "Padding", loc: SourceRange { .. }, value: 12 }), Value(TagValue { id: "Reserved", loc: SourceRange { .. }, value: 13 })], len: BitLen(8) }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. ".type"] = buffer(i, field_len):le_uint()
    if PacketType_enum.by_value[field_values[path .. ".type"]] == nil then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".type"])
    end
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".type"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Payload { display_name: "Body", abbr: "_body_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_body__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: ["SimplePacket", "EnumPacket", "Group_AskBrewHistory", "UnalignedPacket", "ChecksumPacket", "Array_Brew", "GroupConstraint_Packet", "Size_Parent", "Size_Brew", "AbstractParent", "PayloadWithSizeModifier", "Fixed_Teapot", "Padding_PaddedCoffee", "Reserved_DeloreanCoffee"] }
    local field_len = enforce_len_limit(sum_or_nil(0 / 8, field_values[path .. "._body__size"]), buffer(i):len(), tree)
    if SimplePacket_match_constraints(field_values, path) then
        local dissected_len = SimplePacket_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".SimplePacket")
        i = i + dissected_len
    elseif EnumPacket_match_constraints(field_values, path) then
        local dissected_len = EnumPacket_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".EnumPacket")
        i = i + dissected_len
    elseif Group_AskBrewHistory_match_constraints(field_values, path) then
        local dissected_len = Group_AskBrewHistory_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".Group_AskBrewHistory")
        i = i + dissected_len
    elseif UnalignedPacket_match_constraints(field_values, path) then
        local dissected_len = UnalignedPacket_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".UnalignedPacket")
        i = i + dissected_len
    elseif ChecksumPacket_match_constraints(field_values, path) then
        local dissected_len = ChecksumPacket_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".ChecksumPacket")
        i = i + dissected_len
    elseif Array_Brew_match_constraints(field_values, path) then
        local dissected_len = Array_Brew_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".Array_Brew")
        i = i + dissected_len
    elseif GroupConstraint_Packet_match_constraints(field_values, path) then
        local dissected_len = GroupConstraint_Packet_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".GroupConstraint_Packet")
        i = i + dissected_len
    elseif Size_Parent_match_constraints(field_values, path) then
        local dissected_len = Size_Parent_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".Size_Parent")
        i = i + dissected_len
    elseif Size_Brew_match_constraints(field_values, path) then
        local dissected_len = Size_Brew_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".Size_Brew")
        i = i + dissected_len
    elseif AbstractParent_match_constraints(field_values, path) then
        local dissected_len = AbstractParent_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".AbstractParent")
        i = i + dissected_len
    elseif PayloadWithSizeModifier_match_constraints(field_values, path) then
        local dissected_len = PayloadWithSizeModifier_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".PayloadWithSizeModifier")
        i = i + dissected_len
    elseif Fixed_Teapot_match_constraints(field_values, path) then
        local dissected_len = Fixed_Teapot_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".Fixed_Teapot")
        i = i + dissected_len
    elseif Padding_PaddedCoffee_match_constraints(field_values, path) then
        local dissected_len = Padding_PaddedCoffee_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".Padding_PaddedCoffee")
        i = i + dissected_len
    elseif Reserved_DeloreanCoffee_match_constraints(field_values, path) then
        local dissected_len = Reserved_DeloreanCoffee_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".Reserved_DeloreanCoffee")
        i = i + dissected_len
    else
        field_values[path .. "._body_"] = buffer(i, field_len):raw()
        local subtree = tree:add_le(fields[path .. "._body_"].field, buffer(i, field_len))

        i = i + field_len
    end
    return i
end
function TopLevel_match_constraints(field_values, path)
    return true
end
function SimplePacket_protocol_fields(fields, path)
    fields[path .. ".scalar_value"] = AlignedProtoField:new({
        name = "scalar_value",
        abbr = path .. ".scalar_value",
        ftype = ftypes.UINT64,
        bitlen = 64
    })
end
-- Sequence { name: "SimplePacket", fields: [Scalar { display_name: "scalar_value", abbr: "scalar_value", bit_offset: BitLen(0), ftype: FType(Some(BitLen(64))), len: Bounded { referenced_fields: [], constant_factor: BitLen(64) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Simple" }] }
function SimplePacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "scalar_value", abbr: "scalar_value", bit_offset: BitLen(0), ftype: FType(Some(BitLen(64))), len: Bounded { referenced_fields: [], constant_factor: BitLen(64) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(64 / 8), buffer(i):len(), tree)
    field_values[path .. ".scalar_value"] = buffer(i, field_len):uint64()
    local subtree = tree:add_le(fields[path .. ".scalar_value"].field, buffer(i, field_len))

    i = i + field_len
    return i
end
function SimplePacket_match_constraints(field_values, path)
    return PacketType_enum:match("Simple", field_values[path .. ".type"])
end
local Enum_CoffeeAddition_enum = ProtoEnum:new()
Enum_CoffeeAddition_enum:define("Empty", 0)
Enum_CoffeeAddition_enum:define("NonAlcoholic: Cream", 1)
Enum_CoffeeAddition_enum:define("NonAlcoholic: Vanilla", 2)
Enum_CoffeeAddition_enum:define("NonAlcoholic: Chocolate", 3)
Enum_CoffeeAddition_enum:define("NonAlcoholic", {1, 9})
Enum_CoffeeAddition_enum:define("Alcoholic: Whisky", 10)
Enum_CoffeeAddition_enum:define("Alcoholic: Rum", 11)
Enum_CoffeeAddition_enum:define("Alcoholic: Kahlua", 12)
Enum_CoffeeAddition_enum:define("Alcoholic: Aquavit", 13)
Enum_CoffeeAddition_enum:define("Alcoholic", {10, 19})
Enum_CoffeeAddition_enum:define("Custom", {20, 29})
Enum_CoffeeAddition_enum:define("Other", nil)
function EnumPacket_protocol_fields(fields, path)
    fields[path .. ".addition"] = AlignedProtoField:new({
        name = "addition",
        abbr = "addition",
        ftype = ftypes.UINT8,
        valuestring = Enum_CoffeeAddition_enum.matchers,
        base = base.RANGE_STRING
    })
end
-- Sequence { name: "EnumPacket", fields: [Typedef { name: "addition", abbr: "addition", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, endian: LittleEndian }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Enum" }] }
function EnumPacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Typedef { name: "addition", abbr: "addition", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. ".addition"] = buffer(i, field_len):le_uint()
    if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".addition"]] == nil then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".addition"])
    end
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".addition"].field, buffer(i, field_len))
        i = i + field_len
    end
    return i
end
function EnumPacket_match_constraints(field_values, path)
    return PacketType_enum:match("Enum", field_values[path .. ".type"])
end
function Group_AskBrewHistory_protocol_fields(fields, path)
    fields[path .. ".pot"] = AlignedProtoField:new({
        name = "pot",
        abbr = path .. ".pot",
        ftype = ftypes.UINT8,
        bitlen = 8
    })
    fields[path .. ".offset"] = AlignedProtoField:new({
        name = "offset",
        abbr = path .. ".offset",
        ftype = ftypes.UINT8,
        bitlen = 8
    })
    fields[path .. ".limit"] = AlignedProtoField:new({
        name = "limit",
        abbr = path .. ".limit",
        ftype = ftypes.UINT8,
        bitlen = 8
    })
end
-- Sequence { name: "Group_AskBrewHistory", fields: [Scalar { display_name: "pot", abbr: "pot", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "offset", abbr: "offset", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "limit", abbr: "limit", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Group" }] }
function Group_AskBrewHistory_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "pot", abbr: "pot", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. ".pot"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".pot"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "offset", abbr: "offset", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. ".offset"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".offset"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "limit", abbr: "limit", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. ".limit"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".limit"].field, buffer(i, field_len))

    i = i + field_len
    return i
end
function Group_AskBrewHistory_match_constraints(field_values, path)
    return PacketType_enum:match("Group", field_values[path .. ".type"])
end
function UnalignedPacket_protocol_fields(fields, path)
    fields[path .. ".a"] = UnalignedProtoField:new({
        name = "a",
        abbr = path .. ".a",
        ftype = ftypes.UINT8,
        bitoffset = 0,
        bitlen = 3
    })
    fields[path .. ".b"] = UnalignedProtoField:new({
        name = "b",
        abbr = path .. ".b",
        ftype = ftypes.UINT8,
        bitoffset = 3,
        bitlen = 8
    })
    fields[path .. ".c"] = UnalignedProtoField:new({
        name = "c",
        abbr = path .. ".c",
        ftype = ftypes.UINT8,
        bitoffset = 3,
        bitlen = 3
    })
    fields[path .. ".d"] = UnalignedProtoField:new({
        name = "d",
        abbr = path .. ".d",
        ftype = ftypes.UINT8,
        bitoffset = 6,
        bitlen = 3
    })
    fields[path .. ".e"] = UnalignedProtoField:new({
        name = "e",
        abbr = path .. ".e",
        ftype = ftypes.UINT8,
        bitoffset = 1,
        bitlen = 3
    })
end
-- Sequence { name: "UnalignedPacket", fields: [Scalar { display_name: "a", abbr: "a", bit_offset: BitLen(0), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "b", abbr: "b", bit_offset: BitLen(3), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "c", abbr: "c", bit_offset: BitLen(3), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "d", abbr: "d", bit_offset: BitLen(6), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "e", abbr: "e", bit_offset: BitLen(1), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Unaligned" }] }
function UnalignedPacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "a", abbr: "a", bit_offset: BitLen(0), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(3 / 8), buffer(i):len(), tree)
    field_values[path .. ".a"], bitlen = fields[path .. ".a"]:dissect(tree, buffer(i), field_len)

    i = i + bitlen / 8
    -- Scalar { display_name: "b", abbr: "b", bit_offset: BitLen(3), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. ".b"], bitlen = fields[path .. ".b"]:dissect(tree, buffer(i), field_len)

    i = i + bitlen / 8
    -- Scalar { display_name: "c", abbr: "c", bit_offset: BitLen(3), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(3 / 8), buffer(i):len(), tree)
    field_values[path .. ".c"], bitlen = fields[path .. ".c"]:dissect(tree, buffer(i), field_len)

    i = i + bitlen / 8
    -- Scalar { display_name: "d", abbr: "d", bit_offset: BitLen(6), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(3 / 8), buffer(i):len(), tree)
    field_values[path .. ".d"], bitlen = fields[path .. ".d"]:dissect(tree, buffer(i), field_len)

    i = i + bitlen / 8
    -- Scalar { display_name: "e", abbr: "e", bit_offset: BitLen(1), ftype: FType(Some(BitLen(3))), len: Bounded { referenced_fields: [], constant_factor: BitLen(3) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(3 / 8), buffer(i):len(), tree)
    field_values[path .. ".e"], bitlen = fields[path .. ".e"]:dissect(tree, buffer(i), field_len)

    i = i + bitlen / 8
    return i
end
function UnalignedPacket_match_constraints(field_values, path)
    return PacketType_enum:match("Unaligned", field_values[path .. ".type"])
end
function ChecksumPacket_protocol_fields(fields, path)
    fields[path .. ".a"] = AlignedProtoField:new({
        name = "a",
        abbr = path .. ".a",
        ftype = ftypes.UINT16,
        bitlen = 16
    })
    fields[path .. ".b"] = AlignedProtoField:new({
        name = "b",
        abbr = path .. ".b",
        ftype = ftypes.UINT16,
        bitlen = 16
    })
    fields[path .. ".crc"] = AlignedProtoField:new({
        name = "crc",
        abbr = "crc",
        ftype = ftypes.UINT16,
        base = base.HEX,
    })
end
-- Sequence { name: "ChecksumPacket", fields: [Scalar { display_name: "a", abbr: "a", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "b", abbr: "b", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Typedef { name: "crc", abbr: "crc", decl: Checksum { name: "CRC16", len: BitLen(16) }, endian: LittleEndian }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Checksum" }] }
function ChecksumPacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "a", abbr: "a", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(16 / 8), buffer(i):len(), tree)
    field_values[path .. ".a"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".a"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "b", abbr: "b", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(16 / 8), buffer(i):len(), tree)
    field_values[path .. ".b"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".b"].field, buffer(i, field_len))

    i = i + field_len
    -- Typedef { name: "crc", abbr: "crc", decl: Checksum { name: "CRC16", len: BitLen(16) }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(16 / 8), buffer(i):len(), tree)
    field_values[path .. ".crc"] = buffer(i, field_len):le_uint()
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".crc"].field, buffer(i, field_len))
        i = i + field_len
    end
    return i
end
function ChecksumPacket_match_constraints(field_values, path)
    return PacketType_enum:match("Checksum", field_values[path .. ".type"])
end
function Array_Brew_protocol_fields(fields, path)
    fields[path .. ".pots"] = AlignedProtoField:new({
        name = "pots",
        abbr = path .. ".pots",
        ftype = ftypes.UINT8,
        bitlen = 8
    })
    fields[path .. ".additions"] = AlignedProtoField:new({
        name = "additions",
        abbr = "additions",
        ftype = ftypes.UINT8,
        valuestring = Enum_CoffeeAddition_enum.matchers,
        base = base.RANGE_STRING
    })
    fields[path .. ".extra_additions"] = AlignedProtoField:new({
        name = "extra_additions",
        abbr = "extra_additions",
        ftype = ftypes.UINT8,
        valuestring = Enum_CoffeeAddition_enum.matchers,
        base = base.RANGE_STRING
    })
end
-- Sequence { name: "Array_Brew", fields: [ScalarArray { display_name: "pots", abbr: "pots", ftype: FType(Some(BitLen(8))), bit_offset: BitLen(0), item_len: BitLen(8), count: Some(2), size_modifier: None, endian: LittleEndian, pad_to_size: None }, TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: Some(2), size_modifier: None, endian: LittleEndian, pad_to_size: None }, TypedefArray { name: "extra_additions", abbr: "extra_additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Array" }] }
function Array_Brew_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- ScalarArray { display_name: "pots", abbr: "pots", ftype: FType(Some(BitLen(8))), bit_offset: BitLen(0), item_len: BitLen(8), count: Some(2), size_modifier: None, endian: LittleEndian, pad_to_size: None }
    local count = nil_coalesce(field_values[path .. ".pots_count"], 2)
    local len_limit = field_values[path .. ".pots_size"]
    local initial_i = i
    for j=1,count do
        if len_limit ~= nil and i - initial_i >= len_limit then break end
        if i >= buffer:len() then break end -- Exit loop. TODO: Check if this exited earlier than expected
        -- ScalarArray { display_name: "pots", abbr: "pots", ftype: FType(Some(BitLen(8))), bit_offset: BitLen(0), item_len: BitLen(8), count: Some(2), size_modifier: None, endian: LittleEndian, pad_to_size: None }
        local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
        field_values[path .. ".pots"] = buffer(i, field_len):le_uint()
        local subtree = tree:add_le(fields[path .. ".pots"].field, buffer(i, field_len))

        i = i + field_len
    end
    -- TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: Some(2), size_modifier: None, endian: LittleEndian, pad_to_size: None }
    local count = nil_coalesce(field_values[path .. ".additions_count"], 2)
    local len_limit = field_values[path .. ".additions_size"]
    local initial_i = i
    for j=1,count do
        if len_limit ~= nil and i - initial_i >= len_limit then break end
        if i >= buffer:len() then break end -- Exit loop. TODO: Check if this exited earlier than expected
        -- TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: Some(2), size_modifier: None, endian: LittleEndian, pad_to_size: None }
        local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
        field_values[path .. ".additions"] = buffer(i, field_len):le_uint()
        if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".additions"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".additions"])
        end
        if field_len ~= 0 then
            tree:add_le(fields[path .. ".additions"].field, buffer(i, field_len))
            i = i + field_len
        end
    end
    -- TypedefArray { name: "extra_additions", abbr: "extra_additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: None }
    local count = nil_coalesce(field_values[path .. ".extra_additions_count"], 65536)
    local len_limit = field_values[path .. ".extra_additions_size"]
    local initial_i = i
    for j=1,count do
        if len_limit ~= nil and i - initial_i >= len_limit then break end
        if i >= buffer:len() then break end -- Exit loop. TODO: Check if this exited earlier than expected
        -- TypedefArray { name: "extra_additions", abbr: "extra_additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: None }
        local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
        field_values[path .. ".extra_additions"] = buffer(i, field_len):le_uint()
        if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".extra_additions"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".extra_additions"])
        end
        if field_len ~= 0 then
            tree:add_le(fields[path .. ".extra_additions"].field, buffer(i, field_len))
            i = i + field_len
        end
    end
    return i
end
function Array_Brew_match_constraints(field_values, path)
    return PacketType_enum:match("Array", field_values[path .. ".type"])
end
function GroupConstraint_Struct_protocol_fields(fields, path)
    fields[path .. "._fixed_101_4"] = AlignedProtoField:new({
        name = "Fixed value",
        abbr = path .. "._fixed_101_4",
        ftype = ftypes.UINT16,
        bitlen = 16
    })
end
-- Sequence { name: "GroupConstraint_Struct", fields: [Scalar { display_name: "Fixed value", abbr: "_fixed_101_4", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: Some("value == 42") }], children: [], constraints: [] }
function GroupConstraint_Struct_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "Fixed value", abbr: "_fixed_101_4", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: Some("value == 42") }
    local field_len = enforce_len_limit(sum_or_nil(16 / 8), buffer(i):len(), tree)
    field_values[path .. "._fixed_101_4"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. "._fixed_101_4"].field, buffer(i, field_len))
    local value = field_values[path .. "._fixed_101_4"]
    if not (value == 42) then
        subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected `value == 42` where value=" .. tostring(value))
    end

    i = i + field_len
    return i
end
function GroupConstraint_Struct_match_constraints(field_values, path)
    return true
end
function GroupConstraint_Packet_protocol_fields(fields, path)
    fields[path .. "._fixed_101_4"] = AlignedProtoField:new({
        name = "Fixed value",
        abbr = path .. "._fixed_101_4",
        ftype = ftypes.UINT16,
        bitlen = 16
    })
end
-- Sequence { name: "GroupConstraint_Packet", fields: [Typedef { name: "s", abbr: "s", decl: Sequence { name: "GroupConstraint_Struct", fields: [Scalar { display_name: "Fixed value", abbr: "_fixed_101_4", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: Some("value == 42") }], children: [], constraints: [] }, endian: LittleEndian }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "GroupConstraint" }] }
function GroupConstraint_Packet_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Typedef { name: "s", abbr: "s", decl: Sequence { name: "GroupConstraint_Struct", fields: [Scalar { display_name: "Fixed value", abbr: "_fixed_101_4", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: Some("value == 42") }], children: [], constraints: [] }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(16 / 8), buffer(i):len(), tree)
    local subtree = tree:add(buffer(i, field_len), "s")
    local dissected_len = GroupConstraint_Struct_dissect(buffer(i, field_len), pinfo, subtree, fields, path)
    subtree:set_len(dissected_len)
    i = i + dissected_len
    return i
end
function GroupConstraint_Packet_match_constraints(field_values, path)
    return PacketType_enum:match("GroupConstraint", field_values[path .. ".type"])
end
function Size_Parent_protocol_fields(fields, path)
    fields[path .. "._payload__size"] = UnalignedProtoField:new({
        name = "Size(Payload)",
        abbr = path .. "._payload__size",
        ftype = ftypes.UINT8,
        bitoffset = 0,
        bitlen = 2
    })
    fields[path .. "._payload_"] = UnalignedProtoField:new({
        name = "Payload",
        abbr = path .. "._payload_",
        ftype = ftypes.BYTES,
        bitoffset = 2,
        bitlen = nil
    })
end
-- Sequence { name: "Size_Parent", fields: [Scalar { display_name: "Size(Payload)", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(2))), len: Bounded { referenced_fields: [], constant_factor: BitLen(2) }, endian: LittleEndian, validate_expr: None }, Payload { display_name: "Payload", abbr: "_payload_", bit_offset: BitLen(2), ftype: FType(None), len: Bounded { referenced_fields: ["_payload__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Size_Parent" }] }
function Size_Parent_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "Size(Payload)", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(2))), len: Bounded { referenced_fields: [], constant_factor: BitLen(2) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(2 / 8), buffer(i):len(), tree)
    field_values[path .. "._payload__size"], bitlen = fields[path .. "._payload__size"]:dissect(tree, buffer(i), field_len)

    i = i + bitlen / 8
    -- Payload { display_name: "Payload", abbr: "_payload_", bit_offset: BitLen(2), ftype: FType(None), len: Bounded { referenced_fields: ["_payload__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }
    local field_len = enforce_len_limit(sum_or_nil(0 / 8, field_values[path .. "._payload__size"]), buffer(i):len(), tree)
    field_values[path .. "._payload_"], bitlen = fields[path .. "._payload_"]:dissect(tree, buffer(i), field_len)

    i = i + bitlen / 8
    return i
end
function Size_Parent_match_constraints(field_values, path)
    return PacketType_enum:match("Size_Parent", field_values[path .. ".type"])
end
local Size_16bitEnum_enum = ProtoEnum:new()
Size_16bitEnum_enum:define("A", 1)
Size_16bitEnum_enum:define("B", 2)
Size_16bitEnum_enum:define("Custom", {3, 5})
Size_16bitEnum_enum:define("Other", nil)
function Size_Brew_protocol_fields(fields, path)
    fields[path .. ".pot"] = AlignedProtoField:new({
        name = "pot",
        abbr = path .. ".pot",
        ftype = ftypes.UINT8,
        bitlen = 8
    })
    fields[path .. ".additions_size"] = AlignedProtoField:new({
        name = "Size(additions)",
        abbr = path .. ".additions_size",
        ftype = ftypes.UINT8,
        bitlen = 8
    })
    fields[path .. ".additions"] = AlignedProtoField:new({
        name = "additions",
        abbr = "additions",
        ftype = ftypes.UINT8,
        valuestring = Enum_CoffeeAddition_enum.matchers,
        base = base.RANGE_STRING
    })
end
-- Sequence { name: "Size_Brew", fields: [Scalar { display_name: "pot", abbr: "pot", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "Size(additions)", abbr: "additions_size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Size_Array" }] }
function Size_Brew_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "pot", abbr: "pot", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. ".pot"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".pot"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "Size(additions)", abbr: "additions_size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. ".additions_size"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".additions_size"].field, buffer(i, field_len))

    i = i + field_len
    -- TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: None }
    local count = nil_coalesce(field_values[path .. ".additions_count"], 65536)
    local len_limit = field_values[path .. ".additions_size"]
    local initial_i = i
    for j=1,count do
        if len_limit ~= nil and i - initial_i >= len_limit then break end
        if i >= buffer:len() then break end -- Exit loop. TODO: Check if this exited earlier than expected
        -- TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: None }
        local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
        field_values[path .. ".additions"] = buffer(i, field_len):le_uint()
        if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".additions"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".additions"])
        end
        if field_len ~= 0 then
            tree:add_le(fields[path .. ".additions"].field, buffer(i, field_len))
            i = i + field_len
        end
    end
    return i
end
function Size_Brew_match_constraints(field_values, path)
    return PacketType_enum:match("Size_Array", field_values[path .. ".type"])
end
function AbstractParent_protocol_fields(fields, path)
    fields[path .. "._body_"] = AlignedProtoField:new({
        name = "Body",
        abbr = path .. "._body_",
        ftype = ftypes.BYTES,
        bitlen = nil
    })
    ChildWithoutConstraints_protocol_fields(fields, path .. ".ChildWithoutConstraints")
end
-- Sequence { name: "AbstractParent", fields: [Payload { display_name: "Body", abbr: "_body_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_body__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: ["ChildWithoutConstraints"] }], children: [Sequence { name: "ChildWithoutConstraints", fields: [Scalar { display_name: "field", abbr: "field", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "InheritanceWithoutConstraint" }] }
function AbstractParent_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Payload { display_name: "Body", abbr: "_body_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_body__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: ["ChildWithoutConstraints"] }
    local field_len = enforce_len_limit(sum_or_nil(0 / 8, field_values[path .. "._body__size"]), buffer(i):len(), tree)
    if ChildWithoutConstraints_match_constraints(field_values, path) then
        local dissected_len = ChildWithoutConstraints_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".ChildWithoutConstraints")
        i = i + dissected_len
    else
        field_values[path .. "._body_"] = buffer(i, field_len):raw()
        local subtree = tree:add_le(fields[path .. "._body_"].field, buffer(i, field_len))

        i = i + field_len
    end
    return i
end
function AbstractParent_match_constraints(field_values, path)
    return PacketType_enum:match("InheritanceWithoutConstraint", field_values[path .. ".type"])
end
function ChildWithoutConstraints_protocol_fields(fields, path)
    fields[path .. ".field"] = AlignedProtoField:new({
        name = "field",
        abbr = path .. ".field",
        ftype = ftypes.UINT8,
        bitlen = 8
    })
end
-- Sequence { name: "ChildWithoutConstraints", fields: [Scalar { display_name: "field", abbr: "field", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }
function ChildWithoutConstraints_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "field", abbr: "field", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. ".field"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".field"].field, buffer(i, field_len))

    i = i + field_len
    return i
end
function ChildWithoutConstraints_match_constraints(field_values, path)
    return true
end
function PayloadWithSizeModifier_protocol_fields(fields, path)
    fields[path .. ".additions_size"] = AlignedProtoField:new({
        name = "Size(additions)",
        abbr = path .. ".additions_size",
        ftype = ftypes.UINT8,
        bitlen = 8
    })
    fields[path .. ".additions"] = AlignedProtoField:new({
        name = "additions",
        abbr = "additions",
        ftype = ftypes.UINT8,
        valuestring = Enum_CoffeeAddition_enum.matchers,
        base = base.RANGE_STRING
    })
end
-- Sequence { name: "PayloadWithSizeModifier", fields: [Scalar { display_name: "Size(additions)", abbr: "additions_size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }, TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: Some("+2"), endian: LittleEndian, pad_to_size: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "PayloadWithSizeModifier" }] }
function PayloadWithSizeModifier_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "Size(additions)", abbr: "additions_size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. ".additions_size"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".additions_size"].field, buffer(i, field_len))

    i = i + field_len
    -- TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: Some("+2"), endian: LittleEndian, pad_to_size: None }
    local count = nil_coalesce(field_values[path .. ".additions_count"], 65536)
    local len_limit = field_values[path .. ".additions_size"]+2
    local initial_i = i
    for j=1,count do
        if len_limit ~= nil and i - initial_i >= len_limit then break end
        if i >= buffer:len() then break end -- Exit loop. TODO: Check if this exited earlier than expected
        -- TypedefArray { name: "additions", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: Some("+2"), endian: LittleEndian, pad_to_size: None }
        local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
        field_values[path .. ".additions"] = buffer(i, field_len):le_uint()
        if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".additions"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".additions"])
        end
        if field_len ~= 0 then
            tree:add_le(fields[path .. ".additions"].field, buffer(i, field_len))
            i = i + field_len
        end
    end
    return i
end
function PayloadWithSizeModifier_match_constraints(field_values, path)
    return PacketType_enum:match("PayloadWithSizeModifier", field_values[path .. ".type"])
end
function Fixed_Teapot_protocol_fields(fields, path)
    fields[path .. "._fixed_152_2"] = AlignedProtoField:new({
        name = "Fixed value",
        abbr = path .. "._fixed_152_2",
        ftype = ftypes.UINT8,
        bitlen = 8
    })
    fields[path .. "._fixed_0"] = AlignedProtoField:new({
        name = "Fixed value: Empty",
        abbr = path .. "._fixed_0",
        ftype = ftypes.UINT8,
        bitlen = 8
    })
end
-- Sequence { name: "Fixed_Teapot", fields: [Scalar { display_name: "Fixed value", abbr: "_fixed_152_2", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: Some("value == 42") }, Scalar { display_name: "Fixed value: Empty", abbr: "_fixed_0", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: Some("Enum_CoffeeAddition_enum:match(\"Empty\", value)") }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Fixed" }] }
function Fixed_Teapot_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "Fixed value", abbr: "_fixed_152_2", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: Some("value == 42") }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. "._fixed_152_2"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. "._fixed_152_2"].field, buffer(i, field_len))
    local value = field_values[path .. "._fixed_152_2"]
    if not (value == 42) then
        subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected `value == 42` where value=" .. tostring(value))
    end

    i = i + field_len
    -- Scalar { display_name: "Fixed value: Empty", abbr: "_fixed_0", bit_offset: BitLen(0), ftype: FType(Some(BitLen(8))), len: Bounded { referenced_fields: [], constant_factor: BitLen(8) }, endian: LittleEndian, validate_expr: Some("Enum_CoffeeAddition_enum:match(\"Empty\", value)") }
    local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
    field_values[path .. "._fixed_0"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. "._fixed_0"].field, buffer(i, field_len))
    local value = field_values[path .. "._fixed_0"]
    if not (Enum_CoffeeAddition_enum:match("Empty", value)) then
        subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected `Enum_CoffeeAddition_enum:match(\"Empty\", value)` where value=" .. tostring(value))
    end

    i = i + field_len
    return i
end
function Fixed_Teapot_match_constraints(field_values, path)
    return PacketType_enum:match("Fixed", field_values[path .. ".type"])
end
function Padding_PaddedCoffee_protocol_fields(fields, path)
    fields[path .. ".additions"] = AlignedProtoField:new({
        name = "additions (Padded)",
        abbr = "additions",
        ftype = ftypes.UINT8,
        valuestring = Enum_CoffeeAddition_enum.matchers,
        base = base.RANGE_STRING
    })
end
-- Sequence { name: "Padding_PaddedCoffee", fields: [TypedefArray { name: "additions (Padded)", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: Some(10) }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Padding" }] }
function Padding_PaddedCoffee_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- TypedefArray { name: "additions (Padded)", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: Some(10) }
    local count = nil_coalesce(field_values[path .. ".additions (Padded)_count"], 65536)
    local len_limit = field_values[path .. ".additions (Padded)_size"]
    local initial_i = i
    for j=1,count do
        if len_limit ~= nil and i - initial_i >= len_limit then break end
        if i >= buffer:len() then break end -- Exit loop. TODO: Check if this exited earlier than expected
        -- TypedefArray { name: "additions (Padded)", abbr: "additions", decl: Enum { name: "Enum_CoffeeAddition", values: [Value(TagValue { id: "Empty", loc: SourceRange { .. }, value: 0 }), Range(TagRange { id: "NonAlcoholic", loc: SourceRange { .. }, range: 1..=9, tags: [TagValue { id: "Cream", loc: SourceRange { .. }, value: 1 }, TagValue { id: "Vanilla", loc: SourceRange { .. }, value: 2 }, TagValue { id: "Chocolate", loc: SourceRange { .. }, value: 3 }] }), Range(TagRange { id: "Alcoholic", loc: SourceRange { .. }, range: 10..=19, tags: [TagValue { id: "Whisky", loc: SourceRange { .. }, value: 10 }, TagValue { id: "Rum", loc: SourceRange { .. }, value: 11 }, TagValue { id: "Kahlua", loc: SourceRange { .. }, value: 12 }, TagValue { id: "Aquavit", loc: SourceRange { .. }, value: 13 }] }), Range(TagRange { id: "Custom", loc: SourceRange { .. }, range: 20..=29, tags: [] }), Other(TagOther { id: "Other", loc: SourceRange { .. } })], len: BitLen(8) }, count: None, size_modifier: None, endian: LittleEndian, pad_to_size: Some(10) }
        local field_len = enforce_len_limit(sum_or_nil(8 / 8), buffer(i):len(), tree)
        field_values[path .. ".additions (Padded)"] = buffer(i, field_len):le_uint()
        if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".additions (Padded)"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".additions (Padded)"])
        end
        if field_len ~= 0 then
            tree:add_le(fields[path .. ".additions"].field, buffer(i, field_len))
            i = i + field_len
        end
    end
    if i - initial_i < 10 then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected a minimum of 10 octets in field `additions (Padded)`")
    end
    return i
end
function Padding_PaddedCoffee_match_constraints(field_values, path)
    return PacketType_enum:match("Padding", field_values[path .. ".type"])
end
function Reserved_DeloreanCoffee_protocol_fields(fields, path)
    fields[path .. "._reserved_0"] = UnalignedProtoField:new({
        name = "Reserved",
        abbr = path .. "._reserved_0",
        ftype = ftypes.UINT24,
        bitoffset = 0,
        bitlen = 20
    })
end
-- Sequence { name: "Reserved_DeloreanCoffee", fields: [Scalar { display_name: "Reserved", abbr: "_reserved_0", bit_offset: BitLen(0), ftype: FType(Some(BitLen(20))), len: Bounded { referenced_fields: [], constant_factor: BitLen(20) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [EnumMatch { field: "type", enum_type: "PacketType", enum_value: "Reserved" }] }
function Reserved_DeloreanCoffee_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "Reserved", abbr: "_reserved_0", bit_offset: BitLen(0), ftype: FType(Some(BitLen(20))), len: Bounded { referenced_fields: [], constant_factor: BitLen(20) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(20 / 8), buffer(i):len(), tree)
    field_values[path .. "._reserved_0"], bitlen = fields[path .. "._reserved_0"]:dissect(tree, buffer(i), field_len)

    i = i + bitlen / 8
    return i
end
function Reserved_DeloreanCoffee_match_constraints(field_values, path)
    return PacketType_enum:match("Reserved", field_values[path .. ".type"])
end
-- Protocol definition for "TopLevel"
TopLevel_protocol = Proto("TopLevel",  "TopLevel")
local TopLevel_protocol_fields_table = {}
function TopLevel_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "TopLevel"
    local subtree = tree:add(TopLevel_protocol, buffer(), "TopLevel")
    TopLevel_dissect(buffer, pinfo, subtree, TopLevel_protocol_fields_table, "TopLevel")
end
TopLevel_protocol_fields(TopLevel_protocol_fields_table, "TopLevel")
for name,field in pairs(TopLevel_protocol_fields_table) do
    TopLevel_protocol.fields[name] = field.field
end
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8000, TopLevel_protocol)
