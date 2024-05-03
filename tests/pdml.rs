use pdl_dissector::pdml::Pdml;

#[test]
fn test_parse() {
    let pdml_str = include_str!("pdml_example.xml");
    let pdml = quick_xml::de::from_str::<Pdml>(pdml_str).unwrap();
    assert_eq!("toplevel", pdml.packet[0].proto[6].name);
}
