protocol = Proto("PcapFile",  "PcapFile")
protocol.fields = {}
local PcapFile_protocol_fields = {
}
for k,v in pairs(PcapFile_protocol_fields) do protocol.fields[k] = v end
function PcapFile_dissect(buffer, pinfo, tree)
    local i = 0
    local field_values = {}
--
    local field_len = 24
    local subtree = tree:add(buffer(i, field_len), "header")
    local dissected_len = PcapHeader_dissect(buffer(i, field_len), pinfo, subtree)
    subtree:set_len(dissected_len)
    i = i + dissected_len
--
    for j=1,65536 do
        if i >= buffer:len() then break end
        local subtree = tree:add(buffer(i), "records")
        local dissected_len = PcapRecord_dissect(buffer(i), pinfo, subtree)
        subtree:set_len(dissected_len)
        i = i + dissected_len
    end
    return i
end
local PcapHeader_protocol_fields = {
    ["Fixed value: 2712847316"] = ProtoField.new("Fixed value: 2712847316", "PcapFile.header._fixed_", ftypes.UINT32),
    ["version_major"] = ProtoField.new("version_major", "PcapFile.header.version_major", ftypes.UINT16),
    ["version_minor"] = ProtoField.new("version_minor", "PcapFile.header.version_minor", ftypes.UINT16),
    ["thiszone"] = ProtoField.new("thiszone", "PcapFile.header.thiszone", ftypes.UINT32),
    ["sigfigs"] = ProtoField.new("sigfigs", "PcapFile.header.sigfigs", ftypes.UINT32),
    ["snaplen"] = ProtoField.new("snaplen", "PcapFile.header.snaplen", ftypes.UINT32),
    ["network"] = ProtoField.new("network", "PcapFile.header.network", ftypes.UINT32),
}
for k,v in pairs(PcapHeader_protocol_fields) do protocol.fields[k] = v end
function PcapHeader_dissect(buffer, pinfo, tree)
    local i = 0
    local field_values = {}
--
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    field_values["Fixed value: 2712847316"] = buffer(i, field_len):le_uint()
    if not (function (value) return value == 2712847316 end)(field_values["Fixed value: 2712847316"]) then
    tree:add_expert_info(PI_MALFORMED, PI_WARN, "Validation failed: Expected `value == 2712847316`")
end

    if field_len ~= 0 then
        tree:add_le(PcapHeader_protocol_fields["Fixed value: 2712847316"], buffer(i, field_len))
        i = i + field_len
    end
--
    local field_len = enforce_len_limit(2, buffer(i):len(), tree)
    field_values["version_major"] = buffer(i, field_len):raw()
    
    if field_len ~= 0 then
        tree:add_le(PcapHeader_protocol_fields["version_major"], buffer(i, field_len))
        i = i + field_len
    end
--
    local field_len = enforce_len_limit(2, buffer(i):len(), tree)
    field_values["version_minor"] = buffer(i, field_len):raw()
    
    if field_len ~= 0 then
        tree:add_le(PcapHeader_protocol_fields["version_minor"], buffer(i, field_len))
        i = i + field_len
    end
--
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    field_values["thiszone"] = buffer(i, field_len):le_uint()
    
    if field_len ~= 0 then
        tree:add_le(PcapHeader_protocol_fields["thiszone"], buffer(i, field_len))
        i = i + field_len
    end
--
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    field_values["sigfigs"] = buffer(i, field_len):le_uint()
    
    if field_len ~= 0 then
        tree:add_le(PcapHeader_protocol_fields["sigfigs"], buffer(i, field_len))
        i = i + field_len
    end
--
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    field_values["snaplen"] = buffer(i, field_len):le_uint()
    
    if field_len ~= 0 then
        tree:add_le(PcapHeader_protocol_fields["snaplen"], buffer(i, field_len))
        i = i + field_len
    end
--
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    field_values["network"] = buffer(i, field_len):le_uint()
    
    if field_len ~= 0 then
        tree:add_le(PcapHeader_protocol_fields["network"], buffer(i, field_len))
        i = i + field_len
    end
    return i
end
local PcapRecord_protocol_fields = {
    ["ts_sec"] = ProtoField.new("ts_sec", "PcapFile.records.ts_sec", ftypes.UINT32),
    ["ts_usec"] = ProtoField.new("ts_usec", "PcapFile.records.ts_usec", ftypes.UINT32),
    ["_payload__size"] = ProtoField.new("_payload__size", "PcapFile.records._payload__size", ftypes.UINT32),
    ["orig_len"] = ProtoField.new("orig_len", "PcapFile.records.orig_len", ftypes.UINT32),
    ["_payload_"] = ProtoField.new("_payload_", "PcapFile.records._payload_", ftypes.NONE),
}
for k,v in pairs(PcapRecord_protocol_fields) do protocol.fields[k] = v end
function PcapRecord_dissect(buffer, pinfo, tree)
    local i = 0
    local field_values = {}
--
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    field_values["ts_sec"] = buffer(i, field_len):le_uint()
    
    if field_len ~= 0 then
        tree:add_le(PcapRecord_protocol_fields["ts_sec"], buffer(i, field_len))
        i = i + field_len
    end
--
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    field_values["ts_usec"] = buffer(i, field_len):le_uint()
    
    if field_len ~= 0 then
        tree:add_le(PcapRecord_protocol_fields["ts_usec"], buffer(i, field_len))
        i = i + field_len
    end
--
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    field_values["_payload__size"] = buffer(i, field_len):le_uint()
    
    if field_len ~= 0 then
        tree:add_le(PcapRecord_protocol_fields["_payload__size"], buffer(i, field_len))
        i = i + field_len
    end
--
    local field_len = enforce_len_limit(4, buffer(i):len(), tree)
    field_values["orig_len"] = buffer(i, field_len):le_uint()
    
    if field_len ~= 0 then
        tree:add_le(PcapRecord_protocol_fields["orig_len"], buffer(i, field_len))
        i = i + field_len
    end
--
    local field_len = enforce_len_limit(0 + field_values["_payload__size"], buffer(i):len(), tree)
    field_values["_payload_"] = buffer(i, field_len):raw()
    
    if field_len ~= 0 then
        tree:add_le(PcapRecord_protocol_fields["_payload_"], buffer(i, field_len))
        i = i + field_len
    end
    return i
end
function protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = protocol.name
    local subtree = tree:add(protocol, buffer(), "PcapFile")
    PcapFile_dissect(buffer, pinfo, subtree)
end

-- Utils below

function enforce_len_limit(num, limit, tree)
    if num > limit then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Expected " .. num .. " bytes, but only " .. limit .. " bytes remaining")
        return limit
    end
    return num
end
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8000, protocol)
