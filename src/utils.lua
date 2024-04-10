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
