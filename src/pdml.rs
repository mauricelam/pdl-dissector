//! Reference: <https://gitlab.com/wireshark/wireshark/-/blob/master/doc/README.xml-output>

use serde::Deserialize;

/// The `<pdml>` tag.
///
/// # Example
/// ```xml
/// <pdml version="0" creator="wireshark/0.9.17">
/// ```
///
/// The creator is "wireshark" (i.e., the "wireshark" engine. It will always say "wireshark", not
/// "tshark") version 0.9.17.
#[derive(Deserialize)]
pub struct Pdml {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "@creator")]
    pub creator: String,
    pub packet: Vec<Packet>,
}

#[derive(Deserialize)]
pub struct Packet {
    pub proto: Vec<Proto>,
}

/// The `<proto>` tag
#[derive(Deserialize)]
pub struct Proto {
    /// The display filter name for the protocol.
    #[serde(rename = "@name")]
    pub name: String,
    /// The label used to describe this protocol in the protocol tree. This is usually the descriptive name of the
    /// protocol, but it can be modified by dissectors to include more data (tcp can do this)
    #[serde(rename = "@showname")]
    pub showname: Option<String>,
    /// The starting offset within the packet data where this protocol starts
    #[serde(rename = "@pos")]
    pub pos: Option<usize>,
    /// The number of octets in the packet data that this protocol covers
    #[serde(rename = "@size")]
    pub size: Option<usize>,
    pub field: Vec<Field>,
}

/// The `<field>` tag
#[derive(Deserialize)]
pub struct Field {
    /// The display filter name for the field.
    #[serde(rename = "@name")]
    pub name: String,
    /// The label used to describe this field in the protocol tree. This is usually the descriptive name of the
    /// protocol, followed by some representation of the value.
    #[serde(rename = "@showname")]
    pub showname: Option<String>,
    /// The starting offset within the packet data where this field starts
    #[serde(rename = "@pos")]
    pub pos: usize,
    /// The number of octets in the packet data that this field covers
    #[serde(rename = "@size")]
    pub size: usize,
    /// The actual packet data, in hex, that this field covers
    #[serde(rename = "@value")]
    pub value: Option<String>,
    /// The representation of the packet data (`value`) as it would appear in a display filter.
    #[serde(rename = "@show")]
    pub show: Option<String>,
    #[serde(default)]
    pub field: Vec<Field>,
}
