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
    o.field = ProtoField.new(o.name, o.abbr, o.ftype, nil, nil, nil, o.description)
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
    local subtree = tree:add(self.field, buf, value, label)
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
function PcapHeader_protocol_fields(fields, path)
    fields[path .. "._fixed_0"] = AlignedProtoField:new({
        name = "Fixed value",
        abbr = path .. "._fixed_0",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "magic number",
    })
    fields[path .. ".version_major"] = AlignedProtoField:new({
        name = "version_major",
        abbr = path .. ".version_major",
        ftype = ftypes.UINT16,
        bitlen = 16,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".version_minor"] = AlignedProtoField:new({
        name = "version_minor",
        abbr = path .. ".version_minor",
        ftype = ftypes.UINT16,
        bitlen = 16,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".thiszone"] = AlignedProtoField:new({
        name = "thiszone",
        abbr = path .. ".thiszone",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "GMT to local correction",
    })
    fields[path .. ".sigfigs"] = AlignedProtoField:new({
        name = "sigfigs",
        abbr = path .. ".sigfigs",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "accuracy of timestamps",
    })
    fields[path .. ".snaplen"] = AlignedProtoField:new({
        name = "snaplen",
        abbr = path .. ".snaplen",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "max length of captured packets, in octets",
    })
    fields[path .. ".network"] = AlignedProtoField:new({
        name = "network",
        abbr = path .. ".network",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "data link type",
    })
end
-- Sequence: PcapHeader (7 fields, 0 children, 0 constraints)
function PcapHeader_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: Fixed value
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    subtree, field_values[path .. "._fixed_0"], bitlen = fields[path .. "._fixed_0"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    local value = field_values[path .. "._fixed_0"]
    if not (value == 2712847316) then
        subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected `value == 2712847316` where value=" .. tostring(value))
    end
    -- Scalar: version_major
    local field_len = enforce_len_limit(2, buffer(i):len(), tree)
    subtree, field_values[path .. ".version_major"], bitlen = fields[path .. ".version_major"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: version_minor
    local field_len = enforce_len_limit(2, buffer(i):len(), tree)
    subtree, field_values[path .. ".version_minor"], bitlen = fields[path .. ".version_minor"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: thiszone
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    subtree, field_values[path .. ".thiszone"], bitlen = fields[path .. ".thiszone"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: sigfigs
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    subtree, field_values[path .. ".sigfigs"], bitlen = fields[path .. ".sigfigs"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: snaplen
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    subtree, field_values[path .. ".snaplen"], bitlen = fields[path .. ".snaplen"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: network
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    subtree, field_values[path .. ".network"], bitlen = fields[path .. ".network"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    return i
end
function PcapHeader_match_constraints(field_values, path)
    return true
end
function PcapRecord_protocol_fields(fields, path)
    fields[path .. ".ts_sec"] = AlignedProtoField:new({
        name = "ts_sec",
        abbr = path .. ".ts_sec",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "timestamp seconds",
    })
    fields[path .. ".ts_usec"] = AlignedProtoField:new({
        name = "ts_usec",
        abbr = path .. ".ts_usec",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "timestamp microseconds",
    })
    fields[path .. "._payload__size"] = AlignedProtoField:new({
        name = "Size(Payload)",
        abbr = path .. "._payload__size",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "number of octets of packet saved in file",
    })
    fields[path .. ".orig_len"] = AlignedProtoField:new({
        name = "orig_len",
        abbr = path .. ".orig_len",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "actual length of packet",
    })
    fields[path .. "._payload_"] = AlignedProtoField:new({
        name = "Payload",
        abbr = path .. "._payload_",
        ftype = ftypes.BYTES,
        bitlen = nil,
        is_little_endian = true,
        description = "packet octets",
    })
end
-- Sequence: PcapRecord (5 fields, 0 children, 0 constraints)
function PcapRecord_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar: ts_sec
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    subtree, field_values[path .. ".ts_sec"], bitlen = fields[path .. ".ts_sec"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: ts_usec
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    subtree, field_values[path .. ".ts_usec"], bitlen = fields[path .. ".ts_usec"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: Size(Payload)
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    subtree, field_values[path .. "._payload__size"], bitlen = fields[path .. "._payload__size"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Scalar: orig_len
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    subtree, field_values[path .. ".orig_len"], bitlen = fields[path .. ".orig_len"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    -- Payload: Payload
    local field_len = enforce_len_limit(sum_or_nil(0, field_values[path .. "._payload__size"]), buffer(i):len(), tree)
    subtree, field_values[path .. "._payload_"], bitlen = fields[path .. "._payload_"]:dissect(tree, buffer(i), field_len)
    i = i + bitlen / 8
    return i
end
function PcapRecord_match_constraints(field_values, path)
    return true
end
function PcapFile_protocol_fields(fields, path)
    fields[path .. "._fixed_0"] = AlignedProtoField:new({
        name = "Fixed value",
        abbr = path .. "._fixed_0",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "magic number",
    })
    fields[path .. ".version_major"] = AlignedProtoField:new({
        name = "version_major",
        abbr = path .. ".version_major",
        ftype = ftypes.UINT16,
        bitlen = 16,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".version_minor"] = AlignedProtoField:new({
        name = "version_minor",
        abbr = path .. ".version_minor",
        ftype = ftypes.UINT16,
        bitlen = 16,
        is_little_endian = true,
        description = nil,
    })
    fields[path .. ".thiszone"] = AlignedProtoField:new({
        name = "thiszone",
        abbr = path .. ".thiszone",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "GMT to local correction",
    })
    fields[path .. ".sigfigs"] = AlignedProtoField:new({
        name = "sigfigs",
        abbr = path .. ".sigfigs",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "accuracy of timestamps",
    })
    fields[path .. ".snaplen"] = AlignedProtoField:new({
        name = "snaplen",
        abbr = path .. ".snaplen",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "max length of captured packets, in octets",
    })
    fields[path .. ".network"] = AlignedProtoField:new({
        name = "network",
        abbr = path .. ".network",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "data link type",
    })
    fields[path .. ".ts_sec"] = AlignedProtoField:new({
        name = "ts_sec",
        abbr = path .. ".ts_sec",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "timestamp seconds",
    })
    fields[path .. ".ts_usec"] = AlignedProtoField:new({
        name = "ts_usec",
        abbr = path .. ".ts_usec",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "timestamp microseconds",
    })
    fields[path .. "._payload__size"] = AlignedProtoField:new({
        name = "Size(Payload)",
        abbr = path .. "._payload__size",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "number of octets of packet saved in file",
    })
    fields[path .. ".orig_len"] = AlignedProtoField:new({
        name = "orig_len",
        abbr = path .. ".orig_len",
        ftype = ftypes.UINT32,
        bitlen = 32,
        is_little_endian = true,
        description = "actual length of packet",
    })
    fields[path .. "._payload_"] = AlignedProtoField:new({
        name = "Payload",
        abbr = path .. "._payload_",
        ftype = ftypes.BYTES,
        bitlen = nil,
        is_little_endian = true,
        description = "packet octets",
    })
end
-- Sequence: PcapFile (2 fields, 0 children, 0 constraints)
function PcapFile_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Typedef: header
    local field_len = enforce_len_limit(24, buffer(i):len(), tree)
    local subtree = tree:add(buffer(i, field_len), "header")
    local dissected_len = PcapHeader_dissect(buffer(i, field_len), pinfo, subtree, fields, path)
    subtree:set_len(dissected_len)
    i = i + dissected_len
    -- TypedefArray: records
    local initial_i = i
    while i < buffer:len() do    -- TypedefArray: records
        local field_len = enforce_len_limit(sum_or_nil(16, field_values[path .. "._payload__size"]), buffer(i):len(), tree)
        local subtree = tree:add(buffer(i, field_len), "records")
        local dissected_len = PcapRecord_dissect(buffer(i, field_len), pinfo, subtree, fields, path)
        subtree:set_len(dissected_len)
        i = i + dissected_len
    end
    return i
end
function PcapFile_match_constraints(field_values, path)
    return true
end
-- Protocol definition for "PcapFile"
PcapFile_protocol = Proto("PcapFile",  "PcapFile")
PcapFile_protocol_fields_table = {}
function PcapFile_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "PcapFile"
    local subtree = tree:add(PcapFile_protocol, buffer(), "PcapFile")
    local i = PcapFile_dissect(buffer, pinfo, subtree, PcapFile_protocol_fields_table, "PcapFile")
    if buffer(i):len() > 0 then
        local remaining_bytes = buffer:len() - i
        if math.floor(remaining_bytes) == remaining_bytes then
            subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: " .. remaining_bytes .. " undissected bytes remaining")
        else
            subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: " .. (remaining_bytes * 8) .. " undissected bits remaining")
        end
    end
end
PcapFile_protocol_fields(PcapFile_protocol_fields_table, "PcapFile")
for name,field in pairs(PcapFile_protocol_fields_table) do
    PcapFile_protocol.fields[name] = field.field
end
