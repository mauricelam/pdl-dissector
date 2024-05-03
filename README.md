## PDL dissector

Generate Wireshark dissectors from Packet Descriptions written in [PDL](https://github.com/google/pdl).

PDL is a domain specific language for writing the definition of binary protocol packets. By using
this tool, you can generate the lua code for Wireshark dissectors. The output of this tool is lua
function definitions that can be inserted into a Wireshark dissector table.

## Usage

To use this tool, first write a PDL file. See the [PDL project](https://github.com/google/pdl) and
its [language reference](https://github.com/google/pdl/blob/main/doc/reference.md) for information
on how to write your PDL.

For example, if you have this PDL file:

```
little_endian_packets

struct PcapHeader {
  _fixed_ = 0xa1b2c3d4: 32, /* magic number */
  version_major: 16,
  version_minor: 16,
  thiszone: 32,  /* GMT to local correction */
  sigfigs: 32,  /* accuracy of timestamps */
  snaplen: 32,  /* max length of captured packets, in octets */
  network: 32,  /* data link type */
}

struct PcapRecord {
  ts_sec: 32,  /* timestamp seconds */
  ts_usec: 32,  /* timestamp microseconds */
  _size_(_payload_): 32, /* number of octets of packet saved in file */
  orig_len: 32,  /* actual length of packet */
  _payload_,  /* packet octets */
}

packet PcapFile {
  header: PcapHeader,
  records: PcapRecord[],
}
```

you can run this tool:

```sh
# pdl_dissector <PDL FILE> <PACKET NAME>...
pdl_dissector examples/pcap/pcap.pdl PcapFile > examples/pcap/pcap_dissector.lua
```

This will generate a lua dissector file, which has the protocol `PcapFile_protocol` inside. The
protocol can be registered using something like:

```lua
-- Always dissect contents at port 8000 as PCAP
DissectorTable.get("tcp.port"):add(8000, PcapFile_protocol)

-- Alternatively, you can add it as one of the "decode as" dissectors:
DissectorTable.get("tcp.port"):add_for_decode_as(PcapFile_protocol)
```

This can be done by manually adding to the generated file, appending to the file using a bash
script, or using lua's `require`.

For example:

```sh
pdl_dissector examples/pcap/pcap.pdl PcapFile > examples/pcap/pcap_dissector.lua && \
    echo 'DissectorTable.get("tcp.port"):add(8000, PcapFile_protocol)' >> examples/pcap/pcap_dissector.lua
```

For basic usages, this is all you need. Simply place it in the [Wireshark plugin
directory](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) for your platform
and start Wireshark to start using.

> ##### On Windows:
> The personal plugin folder is %APPDATA%\Wireshark\plugins.
> The global plugin folder is WIRESHARK\plugins.
>
> ##### On Unix-like systems:
> The personal plugin folder is ~/.local/lib/wireshark/plugins.

For more advanced usages, consult the [Wireshark
documentation](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html).

## Examples

To see some examples of the generated lua files, see the `examples/` directory. You can also refer
to `tests/integration_test.rs`, which runs the generated dissector and asserts it against the
dissected output.
