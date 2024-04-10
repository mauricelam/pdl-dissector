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

function get_value(buf, is_little_endian)
    local len = buf:len()
    if len >= 1 and len <= 4 then
        if is_little_endian then
            return buf:le_uint()
        else
            return buf:uint()
        end
    elseif len >= 5 and len <= 8 then
        if is_little_endian then
            return buf:le_uint64()
        else
            return buf:uint64()
        end
    else
        return buf:bytes()
    end
end

AlignedProtoField = {}
function AlignedProtoField:new(o)
    local o = o or {
        name = nil,
        abbr = nil,
        ftype = nil,
        valuestring = nil,
        base = nil,
        is_little_endian = nil,
        description = nil, -- optional
    }
    o.field = ProtoField.new(o.name, o.abbr, o.ftype, o.valuestring, o.base, nil, o.description)
    setmetatable(o, self)
    self.__index = self
    return o
end

function AlignedProtoField:dissect(tree, buffer, runtime_len)
    local subtree
    if self.is_little_endian then
        subtree = tree:add_le(self.field, buffer(i, runtime_len))
    else
        subtree = tree:add(self.field, buffer(i, runtime_len))
    end
    return subtree, get_value(buffer(i, runtime_len), self.is_little_endian), runtime_len * 8
end

UnalignedProtoField = {}
function UnalignedProtoField:new(o)
    local o = o or {
        name = nil,
        abbr = nil,
        ftype = nil,
        bitoffset = nil,
        bitlen = nil, -- optional
        valuestring = nil, -- optional
        description = nil, -- optional
    }
    o.field = ProtoField.new(o.name, o.abbr, ftypes.BYTES, nil, nil, nil, o.description)
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
    label = format_bitstring(label) .. " = " .. self.name
    label = label .. ": " .. self:get_value_display_string(value) -- Print out the string label
    local subtree = tree:add(buf, self.field, value, label):set_text(label)
    return subtree, value, bitlen
end

function UnalignedProtoField:get_value_display_string(value)
    if self.valuestring ~= nil then
        for _, range in ipairs(self.valuestring) do
            if range[1] <= value and value <= range[2] then
                return range[3] .. " (" .. value .. ")"
            end
        end
    end
    return value
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

ARRAY_MAX_COUNT = 65536

-- End Utils section
PacketType_enum = ProtoEnum:new()
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
PacketType_enum:define("Optional", 14)
PacketType_enum:define("UnalignedEnum", 15)
function TopLevel_protocol_fields(fields, path)
    fields[path .. ".type"] = AlignedProtoField:new({
        name = "type",
        abbr = "type",
        ftype = ftypes.UINT8,
        valuestring = PacketType_enum.matchers,
        base = base.RANGE_STRING,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. "._body_"] = AlignedProtoField:new({
        name = "Body",
        abbr = path .. "._body_",
        ftype = ftypes.BYTES,
        bitlen = nil,
        is_little_endian = true,
        description = nil,
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
    Optional_CoffeeWithAdditions_protocol_fields(fields, path .. ".Optional_CoffeeWithAdditions")
    UnalignedEnum_packet_protocol_fields(fields, path .. ".UnalignedEnum_packet")
end
-- Sequence: TopLevel (2 fields, 16 children, 0 constraints)
function TopLevel_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Typedef: type
    local field_len = enforce_len_limit(math.ceil(1), buffer(i):len(), tree)
    subtree, field_values[path .. ".type"], bitlen = fields[path .. ".type"]:dissect(tree, buffer(i), field_len)
    if PacketType_enum.by_value[field_values[path .. ".type"]] == nil then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".type"])
    end
    i = i + bitlen / 8
    -- Payload: Body
    local field_len = enforce_len_limit(sum_or_nil(0, field_values[path .. "._body__size"]), buffer(i):len(), tree)
    if SimplePacket_match_constraints(field_values, path) then
        local subtree = tree:add("SimplePacket")
        local dissected_len = SimplePacket_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".SimplePacket")
        i = i + dissected_len
    elseif EnumPacket_match_constraints(field_values, path) then
        local subtree = tree:add("EnumPacket")
        local dissected_len = EnumPacket_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".EnumPacket")
        i = i + dissected_len
    elseif Group_AskBrewHistory_match_constraints(field_values, path) then
        local subtree = tree:add("Group_AskBrewHistory")
        local dissected_len = Group_AskBrewHistory_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".Group_AskBrewHistory")
        i = i + dissected_len
    elseif UnalignedPacket_match_constraints(field_values, path) then
        local subtree = tree:add("UnalignedPacket")
        local dissected_len = UnalignedPacket_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".UnalignedPacket")
        i = i + dissected_len
    elseif ChecksumPacket_match_constraints(field_values, path) then
        local subtree = tree:add("ChecksumPacket")
        local dissected_len = ChecksumPacket_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".ChecksumPacket")
        i = i + dissected_len
    elseif Array_Brew_match_constraints(field_values, path) then
        local subtree = tree:add("Array_Brew")
        local dissected_len = Array_Brew_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".Array_Brew")
        i = i + dissected_len
    elseif GroupConstraint_Packet_match_constraints(field_values, path) then
        local subtree = tree:add("GroupConstraint_Packet")
        local dissected_len = GroupConstraint_Packet_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".GroupConstraint_Packet")
        i = i + dissected_len
    elseif Size_Parent_match_constraints(field_values, path) then
        local subtree = tree:add("Size_Parent")
        local dissected_len = Size_Parent_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".Size_Parent")
        i = i + dissected_len
    elseif Size_Brew_match_constraints(field_values, path) then
        local subtree = tree:add("Size_Brew")
        local dissected_len = Size_Brew_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".Size_Brew")
        i = i + dissected_len
    elseif AbstractParent_match_constraints(field_values, path) then
        local subtree = tree:add("AbstractParent")
        local dissected_len = AbstractParent_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".AbstractParent")
        i = i + dissected_len
    elseif PayloadWithSizeModifier_match_constraints(field_values, path) then
        local subtree = tree:add("PayloadWithSizeModifier")
        local dissected_len = PayloadWithSizeModifier_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".PayloadWithSizeModifier")
        i = i + dissected_len
    elseif Fixed_Teapot_match_constraints(field_values, path) then
        local subtree = tree:add("Fixed_Teapot")
        local dissected_len = Fixed_Teapot_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".Fixed_Teapot")
        i = i + dissected_len
    elseif Padding_PaddedCoffee_match_constraints(field_values, path) then
        local subtree = tree:add("Padding_PaddedCoffee")
        local dissected_len = Padding_PaddedCoffee_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".Padding_PaddedCoffee")
        i = i + dissected_len
    elseif Reserved_DeloreanCoffee_match_constraints(field_values, path) then
        local subtree = tree:add("Reserved_DeloreanCoffee")
        local dissected_len = Reserved_DeloreanCoffee_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".Reserved_DeloreanCoffee")
        i = i + dissected_len
    elseif Optional_CoffeeWithAdditions_match_constraints(field_values, path) then
        local subtree = tree:add("Optional_CoffeeWithAdditions")
        local dissected_len = Optional_CoffeeWithAdditions_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".Optional_CoffeeWithAdditions")
        i = i + dissected_len
    elseif UnalignedEnum_packet_match_constraints(field_values, path) then
        local subtree = tree:add("UnalignedEnum_packet")
        local dissected_len = UnalignedEnum_packet_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".UnalignedEnum_packet")
        i = i + dissected_len
    else
        subtree, field_values[path .. "._body_"], bitlen = fields[path .. "._body_"]:dissect(tree, buffer(i), field_len)
        i = i + bitlen / 8
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
        bitlen = 64,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: SimplePacket (1 fields, 0 children, 1 constraints)
function SimplePacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: scalar_value
    local field_len = enforce_len_limit(8, buffer(i):len(), tree)
    subtree, field_values[path .. ".scalar_value"], bitlen = fields[path .. ".scalar_value"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    return i
end
function SimplePacket_match_constraints(field_values, path)
    return PacketType_enum:match("Simple", field_values[path .. ".type"])
end
Enum_CoffeeAddition_enum = ProtoEnum:new()
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
        base = base.RANGE_STRING,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: EnumPacket (1 fields, 0 children, 1 constraints)
function EnumPacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Typedef: addition
    local field_len = enforce_len_limit(math.ceil(1), buffer(i):len(), tree)
    subtree, field_values[path .. ".addition"], bitlen = fields[path .. ".addition"]:dissect(tree, buffer(i), field_len)
    if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".addition"]] == nil then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".addition"])
    end
    i = i + bitlen / 8
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
        bitlen = 8,
        is_little_endian = true,
        description = "Coffee Pot",
    })
    fields[path .. ".offset"] = AlignedProtoField:new({
        name = "offset",
        abbr = path .. ".offset",
        ftype = ftypes.UINT8,
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".limit"] = AlignedProtoField:new({
        name = "limit",
        abbr = path .. ".limit",
        ftype = ftypes.UINT8,
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: Group_AskBrewHistory (3 fields, 0 children, 1 constraints)
function Group_AskBrewHistory_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: pot
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. ".pot"], bitlen = fields[path .. ".pot"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: offset
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. ".offset"], bitlen = fields[path .. ".offset"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: limit
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. ".limit"], bitlen = fields[path .. ".limit"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
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
        bitlen = 3,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".b"] = UnalignedProtoField:new({
        name = "b",
        abbr = path .. ".b",
        ftype = ftypes.UINT8,
        bitoffset = 3,
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".c"] = UnalignedProtoField:new({
        name = "c",
        abbr = path .. ".c",
        ftype = ftypes.UINT8,
        bitoffset = 3,
        bitlen = 3,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".d"] = UnalignedProtoField:new({
        name = "d",
        abbr = path .. ".d",
        ftype = ftypes.UINT8,
        bitoffset = 6,
        bitlen = 3,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".e"] = UnalignedProtoField:new({
        name = "e",
        abbr = path .. ".e",
        ftype = ftypes.UINT8,
        bitoffset = 1,
        bitlen = 3,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: UnalignedPacket (5 fields, 0 children, 1 constraints)
function UnalignedPacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: a
    local field_len = enforce_len_limit(0.375, buffer(i):len(), tree)
    subtree, field_values[path .. ".a"], bitlen = fields[path .. ".a"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: b
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. ".b"], bitlen = fields[path .. ".b"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: c
    local field_len = enforce_len_limit(0.375, buffer(i):len(), tree)
    subtree, field_values[path .. ".c"], bitlen = fields[path .. ".c"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: d
    local field_len = enforce_len_limit(0.375, buffer(i):len(), tree)
    subtree, field_values[path .. ".d"], bitlen = fields[path .. ".d"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: e
    local field_len = enforce_len_limit(0.375, buffer(i):len(), tree)
    subtree, field_values[path .. ".e"], bitlen = fields[path .. ".e"]:dissect(tree, buffer(i), field_len)
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
        bitlen = 16,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".b"] = AlignedProtoField:new({
        name = "b",
        abbr = path .. ".b",
        ftype = ftypes.UINT16,
        bitlen = 16,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".crc"] = AlignedProtoField:new({
        name = "crc",
        abbr = "crc",
        ftype = ftypes.UINT16,
        base = base.HEX,
        is_little_endian = true,
    })
end
-- Sequence: ChecksumPacket (3 fields, 0 children, 1 constraints)
function ChecksumPacket_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: a
    local field_len = enforce_len_limit(2, buffer(i):len(), tree)
    subtree, field_values[path .. ".a"], bitlen = fields[path .. ".a"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: b
    local field_len = enforce_len_limit(2, buffer(i):len(), tree)
    subtree, field_values[path .. ".b"], bitlen = fields[path .. ".b"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Typedef: crc
    local field_len = enforce_len_limit(2, buffer(i):len(), tree)
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
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".additions"] = AlignedProtoField:new({
        name = "additions",
        abbr = "additions",
        ftype = ftypes.UINT8,
        valuestring = Enum_CoffeeAddition_enum.matchers,
        base = base.RANGE_STRING,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".extra_additions"] = AlignedProtoField:new({
        name = "extra_additions",
        abbr = "extra_additions",
        ftype = ftypes.UINT8,
        valuestring = Enum_CoffeeAddition_enum.matchers,
        base = base.RANGE_STRING,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: Array_Brew (3 fields, 0 children, 1 constraints)
function Array_Brew_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- ScalarArray: pots
    local initial_i = i
    for j=1,2 do
        -- Warn if there isn't enough elements to fit the expected count
        if i >= buffer:len() and j <= 2 then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected 2 `pots` items but only found " .. (j - 1))
            break
        end
        -- ScalarArray: pots
        local field_len = enforce_len_limit(1, buffer(i):len(), tree)
        subtree, field_values[path .. ".pots"], bitlen = fields[path .. ".pots"]:dissect(tree, buffer(i), field_len)
        i = i + bitlen / 8
    end
    -- TypedefArray: additions
    local initial_i = i
    for j=1,2 do
        -- Warn if there isn't enough elements to fit the expected count
        if i >= buffer:len() and j <= 2 then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected 2 `additions` items but only found " .. (j - 1))
            break
        end
        -- TypedefArray: additions
        local field_len = enforce_len_limit(math.ceil(1), buffer(i):len(), tree)
        subtree, field_values[path .. ".additions"], bitlen = fields[path .. ".additions"]:dissect(tree, buffer(i), field_len)
        if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".additions"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".additions"])
        end
        i = i + bitlen / 8
    end
    -- TypedefArray: extra_additions
    local initial_i = i
    while i < buffer:len() do    -- TypedefArray: extra_additions
        local field_len = enforce_len_limit(math.ceil(1), buffer(i):len(), tree)
        subtree, field_values[path .. ".extra_additions"], bitlen = fields[path .. ".extra_additions"]:dissect(tree, buffer(i), field_len)
        if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".extra_additions"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".extra_additions"])
        end
        i = i + bitlen / 8
    end
    return i
end
function Array_Brew_match_constraints(field_values, path)
    return PacketType_enum:match("Array", field_values[path .. ".type"])
end
function GroupConstraint_Struct_protocol_fields(fields, path)
    fields[path .. "._fixed_0"] = AlignedProtoField:new({
        name = "Fixed value",
        abbr = path .. "._fixed_0",
        ftype = ftypes.UINT16,
        bitlen = 16,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: GroupConstraint_Struct (1 fields, 0 children, 0 constraints)
function GroupConstraint_Struct_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: Fixed value
    local field_len = enforce_len_limit(2, buffer(i):len(), tree)
    subtree, field_values[path .. "._fixed_0"], bitlen = fields[path .. "._fixed_0"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    local value = field_values[path .. "._fixed_0"]
    if not (value == 42) then
        subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected `value == 42` where value=" .. tostring(value))
    end
    return i
end
function GroupConstraint_Struct_match_constraints(field_values, path)
    return true
end
function GroupConstraint_Packet_protocol_fields(fields, path)
    fields[path .. "._fixed_0"] = AlignedProtoField:new({
        name = "Fixed value",
        abbr = path .. "._fixed_0",
        ftype = ftypes.UINT16,
        bitlen = 16,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: GroupConstraint_Packet (1 fields, 0 children, 1 constraints)
function GroupConstraint_Packet_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Typedef: s
    local field_len = enforce_len_limit(2, buffer(i):len(), tree)
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
        bitlen = 2,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. "._payload_"] = UnalignedProtoField:new({
        name = "Payload",
        abbr = path .. "._payload_",
        ftype = ftypes.BYTES,
        bitoffset = 2,
        bitlen = nil,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: Size_Parent (2 fields, 0 children, 1 constraints)
function Size_Parent_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: Size(Payload)
    local field_len = enforce_len_limit(0.25, buffer(i):len(), tree)
    subtree, field_values[path .. "._payload__size"], bitlen = fields[path .. "._payload__size"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Payload: Payload
    local field_len = enforce_len_limit(sum_or_nil(0, field_values[path .. "._payload__size"]), buffer(i):len(), tree)
    subtree, field_values[path .. "._payload_"], bitlen = fields[path .. "._payload_"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    return i
end
function Size_Parent_match_constraints(field_values, path)
    return PacketType_enum:match("Size_Parent", field_values[path .. ".type"])
end
Size_16bitEnum_enum = ProtoEnum:new()
Size_16bitEnum_enum:define("A", 1)
Size_16bitEnum_enum:define("B", 2)
Size_16bitEnum_enum:define("Custom", {3, 5})
Size_16bitEnum_enum:define("Other", nil)
function Size_Brew_protocol_fields(fields, path)
    fields[path .. ".pot"] = AlignedProtoField:new({
        name = "pot",
        abbr = path .. ".pot",
        ftype = ftypes.UINT8,
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".additions_size"] = AlignedProtoField:new({
        name = "Size(additions)",
        abbr = path .. ".additions_size",
        ftype = ftypes.UINT8,
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".additions"] = AlignedProtoField:new({
        name = "additions",
        abbr = "additions",
        ftype = ftypes.UINT8,
        valuestring = Enum_CoffeeAddition_enum.matchers,
        base = base.RANGE_STRING,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: Size_Brew (3 fields, 0 children, 1 constraints)
function Size_Brew_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: pot
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. ".pot"], bitlen = fields[path .. ".pot"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: Size(additions)
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. ".additions_size"], bitlen = fields[path .. ".additions_size"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- TypedefArray: additions
    local initial_i = i
    if initial_i + field_values[path .. ".additions_size"] > buffer:len() then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Size(additions) is greater than the number of remaining bytes")
    end
    while i < buffer:len() and i - initial_i < field_values[path .. ".additions_size"] do
        -- TypedefArray: additions
        local field_len = enforce_len_limit(math.ceil(1), buffer(i):len(), tree)
        subtree, field_values[path .. ".additions"], bitlen = fields[path .. ".additions"]:dissect(tree, buffer(i), field_len)
        if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".additions"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".additions"])
        end
        i = i + bitlen / 8
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
        bitlen = nil,
        is_little_endian = true,
        description = nil,
    })
    ChildWithoutConstraints_protocol_fields(fields, path .. ".ChildWithoutConstraints")
end
-- Sequence: AbstractParent (1 fields, 1 children, 1 constraints)
function AbstractParent_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Payload: Body
    local field_len = enforce_len_limit(sum_or_nil(0, field_values[path .. "._body__size"]), buffer(i):len(), tree)
    if ChildWithoutConstraints_match_constraints(field_values, path) then
        local subtree = tree:add("ChildWithoutConstraints")
        local dissected_len = ChildWithoutConstraints_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".ChildWithoutConstraints")
        i = i + dissected_len
    else
        subtree, field_values[path .. "._body_"], bitlen = fields[path .. "._body_"]:dissect(tree, buffer(i), field_len)
        i = i + bitlen / 8
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
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: ChildWithoutConstraints (1 fields, 0 children, 0 constraints)
function ChildWithoutConstraints_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: field
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. ".field"], bitlen = fields[path .. ".field"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
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
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".additions"] = AlignedProtoField:new({
        name = "additions",
        abbr = "additions",
        ftype = ftypes.UINT8,
        valuestring = Enum_CoffeeAddition_enum.matchers,
        base = base.RANGE_STRING,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: PayloadWithSizeModifier (2 fields, 0 children, 1 constraints)
function PayloadWithSizeModifier_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: Size(additions)
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. ".additions_size"], bitlen = fields[path .. ".additions_size"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- TypedefArray: additions
    local initial_i = i
    if initial_i + field_values[path .. ".additions_size"]+2 > buffer:len() then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Size(additions) is greater than the number of remaining bytes")
    end
    while i < buffer:len() and i - initial_i < field_values[path .. ".additions_size"]+2 do
        -- TypedefArray: additions
        local field_len = enforce_len_limit(math.ceil(1), buffer(i):len(), tree)
        subtree, field_values[path .. ".additions"], bitlen = fields[path .. ".additions"]:dissect(tree, buffer(i), field_len)
        if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".additions"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".additions"])
        end
        i = i + bitlen / 8
    end
    return i
end
function PayloadWithSizeModifier_match_constraints(field_values, path)
    return PacketType_enum:match("PayloadWithSizeModifier", field_values[path .. ".type"])
end
function Fixed_Teapot_protocol_fields(fields, path)
    fields[path .. "._fixed_0"] = AlignedProtoField:new({
        name = "Fixed value",
        abbr = path .. "._fixed_0",
        ftype = ftypes.UINT8,
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. "._fixed_1"] = AlignedProtoField:new({
        name = "Fixed value: Empty",
        abbr = path .. "._fixed_1",
        ftype = ftypes.UINT8,
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: Fixed_Teapot (2 fields, 0 children, 1 constraints)
function Fixed_Teapot_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: Fixed value
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. "._fixed_0"], bitlen = fields[path .. "._fixed_0"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    local value = field_values[path .. "._fixed_0"]
    if not (value == 42) then
        subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected `value == 42` where value=" .. tostring(value))
    end
    -- Scalar: Fixed value: Empty
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. "._fixed_1"], bitlen = fields[path .. "._fixed_1"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    local value = field_values[path .. "._fixed_1"]
    if not (Enum_CoffeeAddition_enum:match("Empty", value)) then
        subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected `Enum_CoffeeAddition_enum:match(\"Empty\", value)` where value=" .. tostring(value))
    end
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
        base = base.RANGE_STRING,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: Padding_PaddedCoffee (1 fields, 0 children, 1 constraints)
function Padding_PaddedCoffee_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- TypedefArray: additions (Padded)
    local initial_i = i
    while i < buffer:len() do    -- TypedefArray: additions (Padded)
        local field_len = enforce_len_limit(math.ceil(1), buffer(i):len(), tree)
        subtree, field_values[path .. ".additions (Padded)"], bitlen = fields[path .. ".additions"]:dissect(tree, buffer(i), field_len)
        if Enum_CoffeeAddition_enum.by_value[field_values[path .. ".additions (Padded)"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".additions (Padded)"])
        end
        i = i + bitlen / 8
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
        bitlen = 20,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: Reserved_DeloreanCoffee (1 fields, 0 children, 1 constraints)
function Reserved_DeloreanCoffee_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: Reserved
    local field_len = enforce_len_limit(2.5, buffer(i):len(), tree)
    subtree, field_values[path .. "._reserved_0"], bitlen = fields[path .. "._reserved_0"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    return i
end
function Reserved_DeloreanCoffee_match_constraints(field_values, path)
    return PacketType_enum:match("Reserved", field_values[path .. ".type"])
end
function Optional_Cream_protocol_fields(fields, path)
    fields[path .. ".fat_percentage"] = AlignedProtoField:new({
        name = "fat_percentage",
        abbr = path .. ".fat_percentage",
        ftype = ftypes.UINT8,
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: Optional_Cream (1 fields, 0 children, 0 constraints)
function Optional_Cream_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: fat_percentage
    local field_len = enforce_len_limit(1, buffer(i):len(), tree)
    subtree, field_values[path .. ".fat_percentage"], bitlen = fields[path .. ".fat_percentage"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    return i
end
function Optional_Cream_match_constraints(field_values, path)
    return true
end
Optional_Alcohol_enum = ProtoEnum:new()
Optional_Alcohol_enum:define("WHISKY", 0)
Optional_Alcohol_enum:define("COGNAC", 1)
function Optional_CoffeeWithAdditions_protocol_fields(fields, path)
    fields[path .. ".want_sugar"] = UnalignedProtoField:new({
        name = "want_sugar",
        abbr = path .. ".want_sugar",
        ftype = ftypes.UINT8,
        bitoffset = 0,
        bitlen = 1,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".want_cream"] = UnalignedProtoField:new({
        name = "want_cream",
        abbr = path .. ".want_cream",
        ftype = ftypes.UINT8,
        bitoffset = 1,
        bitlen = 1,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".want_alcohol"] = UnalignedProtoField:new({
        name = "want_alcohol",
        abbr = path .. ".want_alcohol",
        ftype = ftypes.UINT8,
        bitoffset = 2,
        bitlen = 1,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. "._reserved_0"] = UnalignedProtoField:new({
        name = "Reserved",
        abbr = path .. "._reserved_0",
        ftype = ftypes.UINT8,
        bitoffset = 3,
        bitlen = 5,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".sugar"] = AlignedProtoField:new({
        name = "sugar",
        abbr = path .. ".sugar",
        ftype = ftypes.UINT16,
        bitlen = 16,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".fat_percentage"] = AlignedProtoField:new({
        name = "fat_percentage",
        abbr = path .. ".fat_percentage",
        ftype = ftypes.UINT8,
        bitlen = 8,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".alcohol"] = AlignedProtoField:new({
        name = "alcohol",
        abbr = "alcohol",
        ftype = ftypes.UINT8,
        valuestring = Optional_Alcohol_enum.matchers,
        base = base.RANGE_STRING,
        is_little_endian = true,
        description = nil,
    })
end
-- Sequence: Optional_CoffeeWithAdditions (7 fields, 0 children, 1 constraints)
function Optional_CoffeeWithAdditions_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: want_sugar
    local field_len = enforce_len_limit(0.125, buffer(i):len(), tree)
    subtree, field_values[path .. ".want_sugar"], bitlen = fields[path .. ".want_sugar"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: want_cream
    local field_len = enforce_len_limit(0.125, buffer(i):len(), tree)
    subtree, field_values[path .. ".want_cream"], bitlen = fields[path .. ".want_cream"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: want_alcohol
    local field_len = enforce_len_limit(0.125, buffer(i):len(), tree)
    subtree, field_values[path .. ".want_alcohol"], bitlen = fields[path .. ".want_alcohol"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: Reserved
    local field_len = enforce_len_limit(0.625, buffer(i):len(), tree)
    subtree, field_values[path .. "._reserved_0"], bitlen = fields[path .. "._reserved_0"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    if field_values[path .. ".want_sugar"] == 1 then
        -- Scalar: sugar
        local field_len = enforce_len_limit(2, buffer(i):len(), tree)
        subtree, field_values[path .. ".sugar"], bitlen = fields[path .. ".sugar"]:dissect(tree, buffer(i), field_len)
        i = i + bitlen / 8
    end
    if field_values[path .. ".want_cream"] == 1 then
        -- Typedef: cream
        local field_len = enforce_len_limit(1, buffer(i):len(), tree)
        local subtree = tree:add(buffer(i, field_len), "cream")
        local dissected_len = Optional_Cream_dissect(buffer(i, field_len), pinfo, subtree, fields, path)
        subtree:set_len(dissected_len)
        i = i + dissected_len
    end
    if field_values[path .. ".want_alcohol"] == 1 then
        -- Typedef: alcohol
        local field_len = enforce_len_limit(math.ceil(1), buffer(i):len(), tree)
        subtree, field_values[path .. ".alcohol"], bitlen = fields[path .. ".alcohol"]:dissect(tree, buffer(i), field_len)
        if Optional_Alcohol_enum.by_value[field_values[path .. ".alcohol"]] == nil then
            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".alcohol"])
        end
        i = i + bitlen / 8
    end
    return i
end
function Optional_CoffeeWithAdditions_match_constraints(field_values, path)
    return PacketType_enum:match("Optional", field_values[path .. ".type"])
end
UnalignedEnum_enum = ProtoEnum:new()
UnalignedEnum_enum:define("A", 1)
UnalignedEnum_enum:define("B", 2)
UnalignedEnum_enum:define("C", 3)
function UnalignedEnum_packet_protocol_fields(fields, path)
    fields[path .. ".enum1"] = UnalignedProtoField:new({
        name = "enum1",
        abbr = "enum1",
        ftype = ftypes.UINT8,
        valuestring = UnalignedEnum_enum.matchers,
        bitoffset = 0,
        bitlen = 3,
        is_little_endian = true,
    })
    fields[path .. ".enum2"] = UnalignedProtoField:new({
        name = "enum2",
        abbr = "enum2",
        ftype = ftypes.UINT8,
        valuestring = UnalignedEnum_enum.matchers,
        bitoffset = 3,
        bitlen = 3,
        is_little_endian = true,
    })
    fields[path .. ".enum3"] = UnalignedProtoField:new({
        name = "enum3",
        abbr = "enum3",
        ftype = ftypes.UINT8,
        valuestring = UnalignedEnum_enum.matchers,
        bitoffset = 6,
        bitlen = 3,
        is_little_endian = true,
    })
end
-- Sequence: UnalignedEnum_packet (3 fields, 0 children, 1 constraints)
function UnalignedEnum_packet_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Typedef: enum1
    local field_len = enforce_len_limit(math.ceil(0.375), buffer(i):len(), tree)
    subtree, field_values[path .. ".enum1"], bitlen = fields[path .. ".enum1"]:dissect(tree, buffer(i), field_len)
    if UnalignedEnum_enum.by_value[field_values[path .. ".enum1"]] == nil then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".enum1"])
    end
    i = i + bitlen / 8
    -- Typedef: enum2
    local field_len = enforce_len_limit(math.ceil(0.375), buffer(i):len(), tree)
    subtree, field_values[path .. ".enum2"], bitlen = fields[path .. ".enum2"]:dissect(tree, buffer(i), field_len)
    if UnalignedEnum_enum.by_value[field_values[path .. ".enum2"]] == nil then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".enum2"])
    end
    i = i + bitlen / 8
    -- Typedef: enum3
    local field_len = enforce_len_limit(math.ceil(0.375), buffer(i):len(), tree)
    subtree, field_values[path .. ".enum3"], bitlen = fields[path .. ".enum3"]:dissect(tree, buffer(i), field_len)
    if UnalignedEnum_enum.by_value[field_values[path .. ".enum3"]] == nil then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".enum3"])
    end
    i = i + bitlen / 8
    return i
end
function UnalignedEnum_packet_match_constraints(field_values, path)
    return PacketType_enum:match("UnalignedEnum", field_values[path .. ".type"])
end
-- Protocol definition for "TopLevel"
TopLevel_protocol = Proto("TopLevel",  "TopLevel")
TopLevel_protocol_fields_table = {}
function TopLevel_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "TopLevel"
    local subtree = tree:add(TopLevel_protocol, buffer(), "TopLevel")
    local i = TopLevel_dissect(buffer, pinfo, subtree, TopLevel_protocol_fields_table, "TopLevel")
    if buffer(i):len() > 0 then
        local remaining_bytes = buffer:len() - i
        if math.floor(remaining_bytes) == remaining_bytes then
            subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: " .. remaining_bytes .. " undissected bytes remaining")
        else
            subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: " .. (remaining_bytes * 8) .. " undissected bits remaining")
        end
    end
end
TopLevel_protocol_fields(TopLevel_protocol_fields_table, "TopLevel")
for name,field in pairs(TopLevel_protocol_fields_table) do
    TopLevel_protocol.fields[name] = field.field
end
DissectorTable.get("tcp.port"):add(8000, TopLevel_protocol)
