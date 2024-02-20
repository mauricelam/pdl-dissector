protocol = Proto("PcapFile",  "PcapFile")
protocol.fields = {}
local PcapFile_protocol_fields = {
}
for k,v in pairs(PcapFile_protocol_fields) do protocol.fields[k] = v end
function PcapFile_dissect(buffer, pinfo, tree)
local i = 0
local field_offsets = {}
local field_len = 24
local subtree = tree:add(buffer(i, field_len), "PcapHeader")
PcapHeader_dissect(buffer(i, field_len), pinfo, subtree)
i = i + field_len
local field_len = 16
local subtree = tree:add(buffer(i, field_len), "PcapRecord")
PcapRecord_dissect(buffer(i, field_len), pinfo, subtree)
i = i + field_len
end
local PcapHeader_protocol_fields = {
["_fixed_"] = ProtoField.new("_fixed_", "PcapFile.header._fixed_", ftypes.UINT32),
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
local field_offsets = {}
local field_len = 4
field_offsets["_fixed_"] = { start = i, len = field_len }
tree:add_le(PcapHeader_protocol_fields["_fixed_"], buffer(i, field_len))
i = i + field_len
local field_len = 2
field_offsets["version_major"] = { start = i, len = field_len }
tree:add_le(PcapHeader_protocol_fields["version_major"], buffer(i, field_len))
i = i + field_len
local field_len = 2
field_offsets["version_minor"] = { start = i, len = field_len }
tree:add_le(PcapHeader_protocol_fields["version_minor"], buffer(i, field_len))
i = i + field_len
local field_len = 4
field_offsets["thiszone"] = { start = i, len = field_len }
tree:add_le(PcapHeader_protocol_fields["thiszone"], buffer(i, field_len))
i = i + field_len
local field_len = 4
field_offsets["sigfigs"] = { start = i, len = field_len }
tree:add_le(PcapHeader_protocol_fields["sigfigs"], buffer(i, field_len))
i = i + field_len
local field_len = 4
field_offsets["snaplen"] = { start = i, len = field_len }
tree:add_le(PcapHeader_protocol_fields["snaplen"], buffer(i, field_len))
i = i + field_len
local field_len = 4
field_offsets["network"] = { start = i, len = field_len }
tree:add_le(PcapHeader_protocol_fields["network"], buffer(i, field_len))
i = i + field_len
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
local field_offsets = {}
local field_len = 4
field_offsets["ts_sec"] = { start = i, len = field_len }
tree:add_le(PcapRecord_protocol_fields["ts_sec"], buffer(i, field_len))
i = i + field_len
local field_len = 4
field_offsets["ts_usec"] = { start = i, len = field_len }
tree:add_le(PcapRecord_protocol_fields["ts_usec"], buffer(i, field_len))
i = i + field_len
local field_len = 4
field_offsets["_payload__size"] = { start = i, len = field_len }
tree:add_le(PcapRecord_protocol_fields["_payload__size"], buffer(i, field_len))
i = i + field_len
local field_len = 4
field_offsets["orig_len"] = { start = i, len = field_len }
tree:add_le(PcapRecord_protocol_fields["orig_len"], buffer(i, field_len))
i = i + field_len
local field_len = 0
field_offsets["_payload_"] = { start = i, len = field_len }
tree:add_le(PcapRecord_protocol_fields["_payload_"], buffer(i, field_len))
i = i + field_len
end
function protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = protocol.name
    local subtree = tree:add(protocol, buffer(), "PcapFile")
    PcapFile_dissect(buffer, pinfo, subtree)
end

        local tcp_port = DissectorTable.get("tcp.port")
        tcp_port:add(8000, protocol)
        
