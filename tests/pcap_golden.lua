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
        bitlen = nil
    }
    o.field = ProtoField.new(o.name, o.abbr, ftypes.BYTES)
    setmetatable(o, self)
    self.__index = self
    return o
end
-- Adds dissection info into `tree`, and returns (value, bit_length)
function UnalignedProtoField:dissect(tree, buffer)
    local numbytes = math.ceil((self.bitlen + self.bitoffset) / 8)
    local buf = buffer(0, numbytes)
    local value = buf:bitfield(self.bitoffset, self.bitlen)
    local label = string.rep(".", self.bitoffset) -- First add `offset` number of dots to represent insignificant bits
    for i=self.bitoffset,self.bitoffset + self.bitlen-1 do
        label = label  .. buf:bitfield(i, 1) -- Then add the binary value
    end
    -- Then add the remaining insignificant bits as dots
    label = label .. string.rep(".", numbytes * 8 - self.bitlen - self.bitoffset)
    label = format_bitstring(label) .. " = " .. self.name .. ": " .. value -- Print out the string label
    tree:add(buf, self.field, value, label):set_text(label)
    return value, self.bitlen
end

-- Add a space every 4 characters in the string
-- Example: 0010010101 -> 0010 0101 01
function format_bitstring(input)
    return input:gsub("....", "%0 "):gsub(" $", "")
end

-- End Utils section
function PcapHeader_protocol_fields(fields, path)
    fields[path .. ".Fixed value: 2712847316"] = AlignedProtoField:new({
        name = "Fixed value: 2712847316",
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
-- Sequence { name: "PcapHeader", fields: [Scalar { name: "Fixed value: 2712847316", abbr: "_fixed_", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }, Scalar { name: "version_major", abbr: "version_major", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "version_minor", abbr: "version_minor", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "thiszone", abbr: "thiszone", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "sigfigs", abbr: "sigfigs", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "snaplen", abbr: "snaplen", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "network", abbr: "network", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }
function PcapHeader_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { name: "Fixed value: 2712847316", abbr: "_fixed_", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values["Fixed value: 2712847316"] = buffer(i, field_len):uint()
    if not (function (value) return value == 2712847316 end)(field_values["Fixed value: 2712847316"]) then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Validation failed: Expected `value == 2712847316`")
    end

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".Fixed value: 2712847316"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Scalar { name: "version_major", abbr: "version_major", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(16 / 8), buffer(i):len(), tree)
    field_values["version_major"] = buffer(i, field_len):uint()

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".version_major"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Scalar { name: "version_minor", abbr: "version_minor", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(16 / 8), buffer(i):len(), tree)
    field_values["version_minor"] = buffer(i, field_len):uint()

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".version_minor"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Scalar { name: "thiszone", abbr: "thiszone", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values["thiszone"] = buffer(i, field_len):uint()

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".thiszone"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Scalar { name: "sigfigs", abbr: "sigfigs", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values["sigfigs"] = buffer(i, field_len):uint()

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".sigfigs"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Scalar { name: "snaplen", abbr: "snaplen", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values["snaplen"] = buffer(i, field_len):uint()

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".snaplen"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Scalar { name: "network", abbr: "network", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values["network"] = buffer(i, field_len):uint()

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".network"].field, buffer(i, field_len))
        i = i + field_len
    end
    return i
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
    fields[path .. "._payload_:size"] = AlignedProtoField:new({
        name = "_payload_:size",
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
        name = "_payload_",
        abbr = path .. "._payload_",
        ftype = ftypes.BYTES
    })
end
-- Sequence { name: "PcapRecord", fields: [Scalar { name: "ts_sec", abbr: "ts_sec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "ts_usec", abbr: "ts_usec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "_payload_:size", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "orig_len", abbr: "orig_len", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Payload { name: "_payload_", abbr: "_payload_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_payload_:size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [] }
function PcapRecord_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Scalar { name: "ts_sec", abbr: "ts_sec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values["ts_sec"] = buffer(i, field_len):uint()

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".ts_sec"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Scalar { name: "ts_usec", abbr: "ts_usec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values["ts_usec"] = buffer(i, field_len):uint()

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".ts_usec"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Scalar { name: "_payload_:size", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values["_payload_:size"] = buffer(i, field_len):uint()

    if field_len ~= 0 then
        tree:add_le(fields[path .. "._payload_:size"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Scalar { name: "orig_len", abbr: "orig_len", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(32 / 8), buffer(i):len(), tree)
    field_values["orig_len"] = buffer(i, field_len):uint()

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".orig_len"].field, buffer(i, field_len))
        i = i + field_len
    end
    -- Payload { name: "_payload_", abbr: "_payload_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_payload_:size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }
    local field_len = enforce_len_limit(sum_or_nil(0 / 8, field_values["_payload_:size"]), buffer(i):len(), tree)
    field_values["_payload_"] = buffer(i, field_len):raw()
    if field_len ~= 0 then
        if false then -- Just to make the following generated code more uniform
        
        else
            tree:add_le(fields[path .. "._payload_"].field, buffer(i, field_len))
            i = i + field_len
        end
    end
    return i
end
function PcapFile_protocol_fields(fields, path)
end
-- Sequence { name: "PcapFile", fields: [Typedef { name: "header", abbr: "header", decl: Sequence { name: "PcapHeader", fields: [Scalar { name: "Fixed value: 2712847316", abbr: "_fixed_", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }, Scalar { name: "version_major", abbr: "version_major", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "version_minor", abbr: "version_minor", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "thiszone", abbr: "thiszone", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "sigfigs", abbr: "sigfigs", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "snaplen", abbr: "snaplen", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "network", abbr: "network", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }, len: Bounded { referenced_fields: [], constant_factor: BitLen(192) }, endian: LittleEndian }, Array { name: "records", decl: Sequence { name: "PcapRecord", fields: [Scalar { name: "ts_sec", abbr: "ts_sec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "ts_usec", abbr: "ts_usec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "_payload_:size", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "orig_len", abbr: "orig_len", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Payload { name: "_payload_", abbr: "_payload_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_payload_:size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [] }, len: Unbounded, size: None }], children: [], constraints: [] }
function PcapFile_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
    -- Typedef { name: "header", abbr: "header", decl: Sequence { name: "PcapHeader", fields: [Scalar { name: "Fixed value: 2712847316", abbr: "_fixed_", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }, Scalar { name: "version_major", abbr: "version_major", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "version_minor", abbr: "version_minor", bit_offset: BitLen(0), ftype: FType(Some(BitLen(16))), len: Bounded { referenced_fields: [], constant_factor: BitLen(16) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "thiszone", abbr: "thiszone", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "sigfigs", abbr: "sigfigs", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "snaplen", abbr: "snaplen", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "network", abbr: "network", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }, len: Bounded { referenced_fields: [], constant_factor: BitLen(192) }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(192 / 8), buffer(i):len(), tree)
    local subtree = tree:add(buffer(i, field_len), "header")
    local dissected_len = PcapHeader_dissect(buffer(i, field_len), pinfo, subtree, fields, path)
    subtree:set_len(dissected_len)
    i = i + dissected_len
    -- Array { name: "records", decl: Sequence { name: "PcapRecord", fields: [Scalar { name: "ts_sec", abbr: "ts_sec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "ts_usec", abbr: "ts_usec", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "_payload_:size", abbr: "_payload__size", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "orig_len", abbr: "orig_len", bit_offset: BitLen(0), ftype: FType(Some(BitLen(32))), len: Bounded { referenced_fields: [], constant_factor: BitLen(32) }, endian: LittleEndian, validate_expr: None }, Payload { name: "_payload_", abbr: "_payload_", bit_offset: BitLen(0), ftype: FType(None), len: Bounded { referenced_fields: ["_payload_:size"], constant_factor: BitLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [] }, len: Unbounded, size: None }
    local size = field_values["records:count"]
    if size == nil then
        size = 65536
    end
    for j=1,size do
        if i >= buffer:len() then break end
        local subtree = tree:add(buffer(i), "records")
        local dissected_len = PcapRecord_dissect(buffer(i), pinfo, subtree, fields, path)
        subtree:set_len(dissected_len)
        i = i + dissected_len
    end
    return i
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
