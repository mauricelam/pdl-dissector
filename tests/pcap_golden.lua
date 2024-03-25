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
        bitlen = nil, -- optional
    }
    o.field = ProtoField.new(o.name, o.abbr, ftypes.BYTES)
    setmetatable(o, self)
    self.__index = self
    return o
end
-- Adds dissection info into `tree`, and returns (value, bit_length)
function UnalignedProtoField:dissect(tree, buffer, runtime_len)
    local bitlen = self.bitlen
    if bitlen == nil then
        bitlen = runtime_len * 8
    end
    local numbytes = math.ceil((bitlen + self.bitoffset) / 8)
    local buf = buffer(0, numbytes)
    local value = buf:bitfield(self.bitoffset, bitlen)
    local label = string.rep(".", self.bitoffset) -- First add `offset` number of dots to represent insignificant bits
    for i=self.bitoffset,self.bitoffset + bitlen-1 do
        label = label  .. buf:bitfield(i, 1) -- Then add the binary value
    end
    -- Then add the remaining insignificant bits as dots
    label = label .. string.rep(".", numbytes * 8 - bitlen - self.bitoffset)
    label = format_bitstring(label) .. " = " .. self.name .. ": " .. value -- Print out the string label
    tree:add(buf, self.field, value, label):set_text(label)
    return value, bitlen
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
function PcapHeader_protocol_fields(fields, path)
    fields[path .. "._fixed_"] = AlignedProtoField:new({
        name = "Fixed value",
        abbr = path .. "._fixed_",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".version_major"] = AlignedProtoField:new({
        name = "version_major",
        abbr = path .. ".version_major",
        ftype = ftypes.UINT16,
        bitlen = 16
    })
    fields[path .. ".version_minor"] = AlignedProtoField:new({
        name = "version_minor",
        abbr = path .. ".version_minor",
        ftype = ftypes.UINT16,
        bitlen = 16
    })
    fields[path .. ".thiszone"] = AlignedProtoField:new({
        name = "thiszone",
        abbr = path .. ".thiszone",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".sigfigs"] = AlignedProtoField:new({
        name = "sigfigs",
        abbr = path .. ".sigfigs",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".snaplen"] = AlignedProtoField:new({
        name = "snaplen",
        abbr = path .. ".snaplen",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".network"] = AlignedProtoField:new({
        name = "network",
        abbr = path .. ".network",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
end
-- Sequence { name: "PcapHeader", fields: [Scalar { display_name: "Fixed value", abbr: "_fixed_", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }, Scalar { display_name: "version_major", abbr: "version_major", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "version_minor", abbr: "version_minor", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "thiszone", abbr: "thiszone", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "sigfigs", abbr: "sigfigs", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "snaplen", abbr: "snaplen", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "network", abbr: "network", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }
function PcapHeader_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "Fixed value", abbr: "_fixed_", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values[path .. "._fixed_"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. "._fixed_"].field, buffer(i, field_len))
    local value = field_values[path .. "._fixed_"]
    if not (value == 2712847316) then
        subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected `value == 2712847316` where value=" .. tostring(value))
    end

    i = i + field_len
    -- Scalar { display_name: "version_major", abbr: "version_major", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(16 / 8), buffer(i):len(), tree)
    field_values[path .. ".version_major"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".version_major"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "version_minor", abbr: "version_minor", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(16 / 8), buffer(i):len(), tree)
    field_values[path .. ".version_minor"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".version_minor"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "thiszone", abbr: "thiszone", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values[path .. ".thiszone"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".thiszone"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "sigfigs", abbr: "sigfigs", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values[path .. ".sigfigs"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".sigfigs"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "snaplen", abbr: "snaplen", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values[path .. ".snaplen"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".snaplen"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "network", abbr: "network", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values[path .. ".network"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".network"].field, buffer(i, field_len))

    i = i + field_len
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
        bitlen = 32
    })
    fields[path .. ".ts_usec"] = AlignedProtoField:new({
        name = "ts_usec",
        abbr = path .. ".ts_usec",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. "._payload__size"] = AlignedProtoField:new({
        name = "Size(Payload)",
        abbr = path .. "._payload__size",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".orig_len"] = AlignedProtoField:new({
        name = "orig_len",
        abbr = path .. ".orig_len",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. "._payload_"] = AlignedProtoField:new({
        name = "Payload",
        abbr = path .. "._payload_",
        ftype = ftypes.BYTES,
        bitlen = nil
    })
end
-- Sequence { name: "PcapRecord", fields: [Scalar { display_name: "ts_sec", abbr: "ts_sec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "ts_usec", abbr: "ts_usec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "Size(Payload)", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "orig_len", abbr: "orig_len", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Payload { display_name: "Payload", abbr: "_payload_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_payload__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [] }
function PcapRecord_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { display_name: "ts_sec", abbr: "ts_sec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values[path .. ".ts_sec"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".ts_sec"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "ts_usec", abbr: "ts_usec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values[path .. ".ts_usec"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".ts_usec"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "Size(Payload)", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values[path .. "._payload__size"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. "._payload__size"].field, buffer(i, field_len))

    i = i + field_len
    -- Scalar { display_name: "orig_len", abbr: "orig_len", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values[path .. ".orig_len"] = buffer(i, field_len):le_uint()
    local subtree = tree:add_le(fields[path .. ".orig_len"].field, buffer(i, field_len))

    i = i + field_len
    -- Payload { display_name: "Payload", abbr: "_payload_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_payload__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }
    local field_len = enforce_len_limit(sum_or_nil(0 / 8, field_values[path .. "._payload__size"]), buffer(i):len(), tree)
    field_values[path .. "._payload_"] = buffer(i, field_len):raw()
    local subtree = tree:add_le(fields[path .. "._payload_"].field, buffer(i, field_len))

    i = i + field_len
    return i
end
function PcapRecord_match_constraints(field_values, path)
    return true
end
function PcapFile_protocol_fields(fields, path)
    fields[path .. "._fixed_"] = AlignedProtoField:new({
        name = "Fixed value",
        abbr = path .. "._fixed_",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".version_major"] = AlignedProtoField:new({
        name = "version_major",
        abbr = path .. ".version_major",
        ftype = ftypes.UINT16,
        bitlen = 16
    })
    fields[path .. ".version_minor"] = AlignedProtoField:new({
        name = "version_minor",
        abbr = path .. ".version_minor",
        ftype = ftypes.UINT16,
        bitlen = 16
    })
    fields[path .. ".thiszone"] = AlignedProtoField:new({
        name = "thiszone",
        abbr = path .. ".thiszone",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".sigfigs"] = AlignedProtoField:new({
        name = "sigfigs",
        abbr = path .. ".sigfigs",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".snaplen"] = AlignedProtoField:new({
        name = "snaplen",
        abbr = path .. ".snaplen",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".network"] = AlignedProtoField:new({
        name = "network",
        abbr = path .. ".network",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".ts_sec"] = AlignedProtoField:new({
        name = "ts_sec",
        abbr = path .. ".ts_sec",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".ts_usec"] = AlignedProtoField:new({
        name = "ts_usec",
        abbr = path .. ".ts_usec",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. "._payload__size"] = AlignedProtoField:new({
        name = "Size(Payload)",
        abbr = path .. "._payload__size",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. ".orig_len"] = AlignedProtoField:new({
        name = "orig_len",
        abbr = path .. ".orig_len",
        ftype = ftypes.UINT32,
        bitlen = 32
    })
    fields[path .. "._payload_"] = AlignedProtoField:new({
        name = "Payload",
        abbr = path .. "._payload_",
        ftype = ftypes.BYTES,
        bitlen = nil
    })
end
-- Sequence { name: "PcapFile", fields: [Typedef { name: "header", abbr: "header", decl: Sequence { name: "PcapHeader", fields: [Scalar { display_name: "Fixed value", abbr: "_fixed_", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }, Scalar { display_name: "version_major", abbr: "version_major", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "version_minor", abbr: "version_minor", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "thiszone", abbr: "thiszone", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "sigfigs", abbr: "sigfigs", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "snaplen", abbr: "snaplen", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "network", abbr: "network", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }, endian: LittleEndian }, TypedefArray { name: "records", abbr: "records", decl: Sequence { name: "PcapRecord", fields: [Scalar { display_name: "ts_sec", abbr: "ts_sec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "ts_usec", abbr: "ts_usec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "Size(Payload)", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "orig_len", abbr: "orig_len", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Payload { display_name: "Payload", abbr: "_payload_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_payload__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [] }, count: None, size_modifier: None, endian: LittleEndian }], children: [], constraints: [] }
function PcapFile_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Typedef { name: "header", abbr: "header", decl: Sequence { name: "PcapHeader", fields: [Scalar { display_name: "Fixed value", abbr: "_fixed_", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }, Scalar { display_name: "version_major", abbr: "version_major", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "version_minor", abbr: "version_minor", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "thiszone", abbr: "thiszone", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "sigfigs", abbr: "sigfigs", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "snaplen", abbr: "snaplen", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "network", abbr: "network", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(192 / 8), buffer(i):len(), tree)
    local subtree = tree:add(buffer(i, field_len), "header")
    local dissected_len = PcapHeader_dissect(buffer(i, field_len), pinfo, subtree, fields, path)
    subtree:set_len(dissected_len)
    i = i + dissected_len
    -- TypedefArray { name: "records", abbr: "records", decl: Sequence { name: "PcapRecord", fields: [Scalar { display_name: "ts_sec", abbr: "ts_sec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "ts_usec", abbr: "ts_usec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "Size(Payload)", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "orig_len", abbr: "orig_len", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Payload { display_name: "Payload", abbr: "_payload_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_payload__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [] }, count: None, size_modifier: None, endian: LittleEndian }
    local count = nil_coalesce(field_values[path .. ".records_count"], 65536)
    local len_limit = field_values[path .. ".records_size"]
    local initial_i = i
    for j=1,count do
        if len_limit ~= nil and i - initial_i >= len_limit then break end
        if i >= buffer:len() then break end -- Exit loop. TODO: Check if this exited earlier than expected
        -- TypedefArray { name: "records", abbr: "records", decl: Sequence { name: "PcapRecord", fields: [Scalar { display_name: "ts_sec", abbr: "ts_sec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "ts_usec", abbr: "ts_usec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "Size(Payload)", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { display_name: "orig_len", abbr: "orig_len", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Payload { display_name: "Payload", abbr: "_payload_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_payload__size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [] }, count: None, size_modifier: None, endian: LittleEndian }
        local field_len = enforce_len_limit(sum_or_nil(128 / 8, field_values[path .. "._payload__size"]), buffer(i):len(), tree)
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
local PcapFile_protocol_fields_table = {}
function PcapFile_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "PcapFile"
    local subtree = tree:add(PcapFile_protocol, buffer(), "PcapFile")
    PcapFile_dissect(buffer, pinfo, subtree, PcapFile_protocol_fields_table, "PcapFile")
end
PcapFile_protocol_fields(PcapFile_protocol_fields_table, "PcapFile")
for name,field in pairs(PcapFile_protocol_fields_table) do
    PcapFile_protocol.fields[name] = field.field
end
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8000, PcapFile_protocol)
