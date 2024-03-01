function PcapHeader_protocol_fields(fields, path)
    fields[path .. ".Fixed value: 2712847316"] = ProtoField.new("Fixed value: 2712847316", "_fixed_", ftypes.UINT32)
    fields[path .. ".version_major"] = ProtoField.new("version_major", "version_major", ftypes.UINT16)
    fields[path .. ".version_minor"] = ProtoField.new("version_minor", "version_minor", ftypes.UINT16)
    fields[path .. ".thiszone"] = ProtoField.new("thiszone", "thiszone", ftypes.UINT32)
    fields[path .. ".sigfigs"] = ProtoField.new("sigfigs", "sigfigs", ftypes.UINT32)
    fields[path .. ".snaplen"] = ProtoField.new("snaplen", "snaplen", ftypes.UINT32)
    fields[path .. ".network"] = ProtoField.new("network", "network", ftypes.UINT32)
end
-- Sequence { name: "PcapHeader", fields: [Scalar { name: "Fixed value: 2712847316", abbr: "_fixed_", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }, Scalar { name: "version_major", abbr: "version_major", ftype: "ftypes.UINT16", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(2) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "version_minor", abbr: "version_minor", ftype: "ftypes.UINT16", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(2) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "thiszone", abbr: "thiszone", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "sigfigs", abbr: "sigfigs", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "snaplen", abbr: "snaplen", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "network", abbr: "network", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }
function PcapHeader_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Scalar { name: "Fixed value: 2712847316", abbr: "_fixed_", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }
    local field_len = enforce_len_limit(sum_or_nil(4), buffer(i):len(), tree)
    field_values["Fixed value: 2712847316"] = buffer(i, field_len):uint()
    if not (function (value) return value == 2712847316 end)(field_values["Fixed value: 2712847316"]) then
    tree:add_expert_info(PI_MALFORMED, PI_WARN, "Validation failed: Expected `value == 2712847316`")
end

    if field_len ~= 0 then
        tree:add_le(fields[path .. ".Fixed value: 2712847316"], buffer(i, field_len))
        i = i + field_len
    end
-- Scalar { name: "version_major", abbr: "version_major", ftype: "ftypes.UINT16", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(2) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(2), buffer(i):len(), tree)
    field_values["version_major"] = buffer(i, field_len):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".version_major"], buffer(i, field_len))
        i = i + field_len
    end
-- Scalar { name: "version_minor", abbr: "version_minor", ftype: "ftypes.UINT16", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(2) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(2), buffer(i):len(), tree)
    field_values["version_minor"] = buffer(i, field_len):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".version_minor"], buffer(i, field_len))
        i = i + field_len
    end
-- Scalar { name: "thiszone", abbr: "thiszone", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(4), buffer(i):len(), tree)
    field_values["thiszone"] = buffer(i, field_len):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".thiszone"], buffer(i, field_len))
        i = i + field_len
    end
-- Scalar { name: "sigfigs", abbr: "sigfigs", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(4), buffer(i):len(), tree)
    field_values["sigfigs"] = buffer(i, field_len):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".sigfigs"], buffer(i, field_len))
        i = i + field_len
    end
-- Scalar { name: "snaplen", abbr: "snaplen", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(4), buffer(i):len(), tree)
    field_values["snaplen"] = buffer(i, field_len):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".snaplen"], buffer(i, field_len))
        i = i + field_len
    end
-- Scalar { name: "network", abbr: "network", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(4), buffer(i):len(), tree)
    field_values["network"] = buffer(i, field_len):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".network"], buffer(i, field_len))
        i = i + field_len
    end
    return i
end
function PcapRecord_protocol_fields(fields, path)
    fields[path .. ".ts_sec"] = ProtoField.new("ts_sec", "ts_sec", ftypes.UINT32)
    fields[path .. ".ts_usec"] = ProtoField.new("ts_usec", "ts_usec", ftypes.UINT32)
    fields[path .. "._payload_:size"] = ProtoField.new("_payload_:size", "_payload__size", ftypes.UINT32)
    fields[path .. ".orig_len"] = ProtoField.new("orig_len", "orig_len", ftypes.UINT32)
    fields[path .. "._payload_"] = ProtoField.new("_payload_", "_payload_", ftypes.BYTES)
end
-- Sequence { name: "PcapRecord", fields: [Scalar { name: "ts_sec", abbr: "ts_sec", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "ts_usec", abbr: "ts_usec", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "_payload_:size", abbr: "_payload__size", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "orig_len", abbr: "orig_len", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Payload { name: "_payload_", abbr: "_payload_", ftype: "ftypes.BYTES", len_bytes: Bounded { referenced_fields: ["_payload_:size"], constant_factor: ByteLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [] }
function PcapRecord_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Scalar { name: "ts_sec", abbr: "ts_sec", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(4), buffer(i):len(), tree)
    field_values["ts_sec"] = buffer(i, field_len):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".ts_sec"], buffer(i, field_len))
        i = i + field_len
    end
-- Scalar { name: "ts_usec", abbr: "ts_usec", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(4), buffer(i):len(), tree)
    field_values["ts_usec"] = buffer(i, field_len):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".ts_usec"], buffer(i, field_len))
        i = i + field_len
    end
-- Scalar { name: "_payload_:size", abbr: "_payload__size", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(4), buffer(i):len(), tree)
    field_values["_payload_:size"] = buffer(i, field_len):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. "._payload_:size"], buffer(i, field_len))
        i = i + field_len
    end
-- Scalar { name: "orig_len", abbr: "orig_len", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }
    local field_len = enforce_len_limit(sum_or_nil(4), buffer(i):len(), tree)
    field_values["orig_len"] = buffer(i, field_len):uint()
    
    if field_len ~= 0 then
        tree:add_le(fields[path .. ".orig_len"], buffer(i, field_len))
        i = i + field_len
    end
-- Payload { name: "_payload_", abbr: "_payload_", ftype: "ftypes.BYTES", len_bytes: Bounded { referenced_fields: ["_payload_:size"], constant_factor: ByteLen(0) }, endian: LittleEndian, children: [] }
    local field_len = enforce_len_limit(sum_or_nil(0, field_values["_payload_:size"]), buffer(i):len(), tree)
    field_values["_payload_"] = buffer(i, field_len):raw()
    if field_len ~= 0 then
        if false then -- Just to make the following generated code more uniform
        
        else
            tree:add_le(fields[path .. "._payload_"], buffer(i, field_len))
            i = i + field_len
        end
    end
    return i
end
function PcapFile_protocol_fields(fields, path)
end
-- Sequence { name: "PcapFile", fields: [Typedef { name: "header", abbr: "header", decl: Sequence { name: "PcapHeader", fields: [Scalar { name: "Fixed value: 2712847316", abbr: "_fixed_", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }, Scalar { name: "version_major", abbr: "version_major", ftype: "ftypes.UINT16", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(2) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "version_minor", abbr: "version_minor", ftype: "ftypes.UINT16", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(2) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "thiszone", abbr: "thiszone", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "sigfigs", abbr: "sigfigs", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "snaplen", abbr: "snaplen", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "network", abbr: "network", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }, len: Bounded { referenced_fields: [], constant_factor: ByteLen(24) }, endian: LittleEndian }, Array { name: "records", decl: Sequence { name: "PcapRecord", fields: [Scalar { name: "ts_sec", abbr: "ts_sec", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "ts_usec", abbr: "ts_usec", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "_payload_:size", abbr: "_payload__size", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "orig_len", abbr: "orig_len", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Payload { name: "_payload_", abbr: "_payload_", ftype: "ftypes.BYTES", len_bytes: Bounded { referenced_fields: ["_payload_:size"], constant_factor: ByteLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [] }, len: Unbounded, size: None }], children: [], constraints: [] }
function PcapFile_dissect(buffer, pinfo, tree, fields, path)
    local i = 0
    local field_values = {}
-- Typedef { name: "header", abbr: "header", decl: Sequence { name: "PcapHeader", fields: [Scalar { name: "Fixed value: 2712847316", abbr: "_fixed_", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: Some("value == 2712847316") }, Scalar { name: "version_major", abbr: "version_major", ftype: "ftypes.UINT16", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(2) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "version_minor", abbr: "version_minor", ftype: "ftypes.UINT16", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(2) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "thiszone", abbr: "thiszone", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "sigfigs", abbr: "sigfigs", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "snaplen", abbr: "snaplen", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "network", abbr: "network", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }], children: [], constraints: [] }, len: Bounded { referenced_fields: [], constant_factor: ByteLen(24) }, endian: LittleEndian }
    local field_len = enforce_len_limit(sum_or_nil(24), buffer(i):len(), tree)
    local subtree = tree:add(buffer(i, field_len), "header")
    local dissected_len = PcapHeader_dissect(buffer(i, field_len), pinfo, subtree, fields, path)
    subtree:set_len(dissected_len)
    i = i + dissected_len
-- Array { name: "records", decl: Sequence { name: "PcapRecord", fields: [Scalar { name: "ts_sec", abbr: "ts_sec", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "ts_usec", abbr: "ts_usec", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "_payload_:size", abbr: "_payload__size", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Scalar { name: "orig_len", abbr: "orig_len", ftype: "ftypes.UINT32", len_bytes: Bounded { referenced_fields: [], constant_factor: ByteLen(4) }, endian: LittleEndian, validate_expr: None }, Payload { name: "_payload_", abbr: "_payload_", ftype: "ftypes.BYTES", len_bytes: Bounded { referenced_fields: ["_payload_:size"], constant_factor: ByteLen(0) }, endian: LittleEndian, children: [] }], children: [], constraints: [] }, len: Unbounded, size: None }
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
function PcapFile_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "PcapFile"
    local subtree = tree:add(PcapFile_protocol, buffer(), "PcapFile")
    PcapFile_dissect(buffer, pinfo, subtree, PcapFile_protocol.fields, "PcapFile")
end
PcapFile_protocol.fields = {}
PcapFile_protocol_fields(PcapFile_protocol.fields, "PcapFile")
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8000, PcapFile_protocol)
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
