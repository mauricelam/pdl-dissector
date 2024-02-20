use anyhow::anyhow;
use clap::Parser;
use log::debug;
use pdl_compiler::{
    analyzer::{self, ast::Size},
    ast::{Annotation, Decl, DeclDesc, EndiannessValue, Field, FieldDesc, File, SourceDatabase},
};
use std::fmt::Write;

// mongodb_protocol = Proto("MongoDB",  "MongoDB Protocol")
// message_length = ProtoField.int32("mongodb.message_length", "messageLength", base.DEC)
// mongodb_protocol.fields = { message_length }

// function mongodb_protocol.dissector(buffer, pinfo, tree)
//   length = buffer:len()
//   if length == 0 then return end

//   pinfo.cols.protocol = mongodb_protocol.name

//   local subtree = tree:add(mongodb_protocol, buffer(), "MongoDB Protocol Data")

//   subtree:add_le(message_length, buffer(0,4))
// end

// local tcp_port = DissectorTable.get("tcp.port")
// tcp_port:add(59274, mongodb_protocol)

#[derive(Clone, Debug)]
struct Context {
    prefix: Vec<String>,
    file: File<analyzer::ast::Annotation>,
    endian: EndiannessValue,
}

impl Context {
    pub fn with_prefix(&self, prefix: impl Into<String>) -> Context {
        let mut result = self.clone();
        result.prefix.push(prefix.into());
        result
    }

    pub fn find_decl(&self, type_id: &str) -> Option<&Decl<analyzer::ast::Annotation>> {
        self.file.declarations.iter().find(|decl| match &decl.desc {
            DeclDesc::Checksum { id, .. }
            | DeclDesc::CustomField { id, .. }
            | DeclDesc::Enum { id, .. }
            | DeclDesc::Packet { id, .. }
            | DeclDesc::Struct { id, .. }
            | DeclDesc::Group { id, .. } => id == type_id,
            DeclDesc::Test { .. } => false,
        })
    }

    pub fn full_field_name(&self, name: &str) -> String {
        let mut full_name = self.prefix.clone();
        full_name.push(name.to_owned());
        full_name.join(".")
    }
}

trait DissectorInfo {
    fn collect_reachable_decls(&self, add_decl: &mut impl FnMut(DeclDissectorInfo));
}

impl<T: DissectorInfo> DissectorInfo for Option<T> {
    fn collect_reachable_decls(&self, add_decl: &mut impl FnMut(DeclDissectorInfo)) {
        if let Some(info) = self {
            info.collect_reachable_decls(add_decl);
        }
    }
}

trait ToDissector {
    type Info: DissectorInfo;

    fn to_dissector_info(&self, ctx: &Context) -> Self::Info;
}

#[derive(Debug, Clone)]
pub struct DeclDissectorInfo {
    name: String,
    fields: Vec<FieldDissectorInfo>,
}

impl DeclDissectorInfo {
    fn write_proto_fields(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        let field_decls: Vec<(String, String)> = self
            .fields
            .iter()
            .filter_map(|f| f.field_declaration())
            .collect();
        writeln!(writer, r#"local {}_protocol_fields = {{"#, self.name)?;
        for (name, decl) in field_decls {
            writeln!(writer, r#"["{name}"] = {decl},"#)?;
        }
        writeln!(writer, r#"}}"#)?;
        Ok(())
    }

    pub fn write_main_dissector(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        writeln!(
            writer,
            r#"function protocol.dissector(buffer, pinfo, tree)"#
        )?;
        writeln!(writer, r#"    pinfo.cols.protocol = protocol.name"#)?;
        writeln!(
            writer,
            r#"    local subtree = tree:add(protocol, buffer(), "{}")"#,
            self.name
        )?;
        writeln!(
            writer,
            r#"    {}_dissect(buffer, pinfo, subtree)"#,
            self.name
        )?;
        writeln!(writer, r#"end"#)?;
        Ok(())
    }

    pub fn decl_len(&self) -> FieldLen {
        let mut field_len = FieldLen::fixed(0);
        for field in &self.fields {
            field_len.add(field.len());
        }
        field_len
    }

    pub fn write_dissect_fn(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        writeln!(
            writer,
            "function {}_dissect(buffer, pinfo, tree)",
            self.name
        )?;
        writeln!(writer, "  local i = 0")?;
        writeln!(writer, "  local field_values = {{}}")?;
        let field_table = format!("{}_protocol_fields", self.name);
        for field in &self.fields {
            field.write_dissect_fn(writer, &field_table)?;
        }
        writeln!(writer, "  return i")?;
        writeln!(writer, "end")?;
        Ok(())
    }
}

impl DissectorInfo for DeclDissectorInfo {
    fn collect_reachable_decls(&self, add_decl: &mut impl FnMut(DeclDissectorInfo)) {
        add_decl(self.clone());
        for field in &self.fields {
            field.collect_reachable_decls(add_decl);
        }
    }
}

impl ToDissector for Decl<analyzer::ast::Annotation> {
    type Info = DeclDissectorInfo;

    fn to_dissector_info(&self, ctx: &Context) -> Self::Info {
        DeclDissectorInfo {
            name: get_desc_id(&self.desc),
            fields: self
                .fields()
                .filter_map(|field| field.to_dissector_info(ctx))
                .collect(),
        }
        // if let (Some(payload), Some(payload_size)) = (self.payload(), self.payload_size()) {

        // }
    }
}

#[derive(Debug, Clone)]
pub enum FieldLen {
    Bounded {
        referenced_fields: Vec<String>,
        constant_factor: usize,
        multiply_factor: usize,
    },
    Unbounded,
}

impl FieldLen {
    pub fn fixed(size: usize) -> Self {
        Self::Bounded {
            referenced_fields: Vec::new(),
            constant_factor: size,
            multiply_factor: 1,
        }
    }

    pub fn add_len_field(&mut self, field: String, modifier: usize) {
        match self {
            FieldLen::Bounded {
                referenced_fields,
                constant_factor,
                multiply_factor: _,
            } => {
                *constant_factor += modifier;
                referenced_fields.push(field);
            }
            FieldLen::Unbounded => *self = FieldLen::Unbounded,
        }
    }

    pub fn add(&mut self, other: &FieldLen) {
        *self = match (&self, other) {
            (
                FieldLen::Bounded {
                    referenced_fields,
                    constant_factor,
                    multiply_factor,
                },
                FieldLen::Bounded {
                    referenced_fields: other_referenced_fields,
                    constant_factor: other_constant_factor,
                    multiply_factor: other_multiply_factor,
                },
            ) => {
                assert_eq!(1, *multiply_factor); // Needs some refactoring before this can accept multiple fixed-sized arrays
                assert_eq!(1, *other_multiply_factor);
                FieldLen::Bounded {
                    referenced_fields: [referenced_fields.as_slice(), &other_referenced_fields]
                        .concat(),
                    constant_factor: constant_factor + other_constant_factor,
                    multiply_factor: 1,
                }
            }
            _ => FieldLen::Unbounded,
        }
    }

    /// Prints the lua code to calculate the buffer for this len. Assumes the
    /// following lua variables are in scope:
    ///
    /// Returns an option that is `None` if this length is unbounded, otherwise
    /// returns a lua expression for the field length.
    pub fn to_lua_expr(&self) -> Option<String> {
        match self {
            FieldLen::Bounded {
                referenced_fields,
                constant_factor,
                multiply_factor,
            } => {
                let len = constant_factor * multiply_factor;
                let mut output_code = len.to_string();
                for field in referenced_fields {
                    write!(output_code, r#" + field_values["{field}"]"#).unwrap();
                }
                Some(output_code)
            }
            FieldLen::Unbounded => None,
        }
    }
}

#[derive(Debug, Clone)]
enum FieldDissectorInfo {
    Scalar {
        /// Actual name of the field (the string that appears in the tree).
        name: String,
        /// Filter name of the field (the string that is used in filters).
        abbr: String,
        ftype: &'static str,
        size: Size,
        len: FieldLen,
        endian: EndiannessValue,
    },
    Typedef {
        name: String,
        decl: Box<DeclDissectorInfo>,
        len: FieldLen,
    },
    Array {
        name: String,
        decl: Box<DeclDissectorInfo>,
        len: FieldLen,
        size: Option<usize>,
    },
}

impl FieldDissectorInfo {
    /// Returns a pair (field_name, lua_expression), or `None` if no ProtoFields
    /// need to be defined.
    pub fn field_declaration(&self) -> Option<(String, String)> {
        match self {
            FieldDissectorInfo::Scalar {
                name, abbr, ftype, ..
            } => Some((
                name.to_string(),
                format!(r#"ProtoField.new("{name}", "{abbr}", {ftype})"#),
            )),
            FieldDissectorInfo::Typedef { .. } => None,
            FieldDissectorInfo::Array { .. } => None,
        }
    }

    pub fn len(&self) -> &FieldLen {
        match self {
            FieldDissectorInfo::Scalar { len, .. } => len,
            FieldDissectorInfo::Typedef { len, .. } => len,
            FieldDissectorInfo::Array { len, .. } => len,
        }
    }

    pub fn write_dissect_fn(
        &self,
        writer: &mut impl std::io::Write,
        field_table: &str,
    ) -> std::io::Result<()> {
        match self {
            FieldDissectorInfo::Scalar {
                name, endian, size, ..
            } => {
                let add_fn = match endian {
                    EndiannessValue::LittleEndian => "add_le",
                    EndiannessValue::BigEndian => "add",
                };
                let (len_expr, buffer_expr) = if let Some(len_expr) = self.len().to_lua_expr() {
                    (len_expr, "buffer(i, field_len)")
                } else {
                    ("0".into(), "buffer(i)")
                };
                writeln!(writer, r#"  local field_len = {len_expr}"#)?;
                let buffer_value_function = match (endian, size) {
                    (EndiannessValue::BigEndian, Size::Static(64)) => "uint64",
                    (EndiannessValue::LittleEndian, Size::Static(64)) => "le_uint64",
                    (EndiannessValue::BigEndian, Size::Static(32)) => "uint",
                    (EndiannessValue::LittleEndian, Size::Static(32)) => "le_uint",
                    (EndiannessValue::BigEndian, _) => "raw",
                    (EndiannessValue::LittleEndian, _) => "raw",
                };
                writeln!(
                    writer,
                    r#"  field_values["{name}"] = {buffer_expr}:{buffer_value_function}()"#
                )?;
                writeln!(
                    writer,
                    r#"  tree:{add_fn}({field_table}["{name}"], {buffer_expr})"#,
                )?;
                writeln!(writer, "  i = i + field_len")?;
            }
            FieldDissectorInfo::Array { name, decl, len, size } => {
                let (len_expr, buffer_expr) = if let Some(len_expr) = len.to_lua_expr() {
                    (len_expr, "buffer(i, field_len)")
                } else {
                    ("0".into(), "buffer(i)")
                };
                writeln!(writer, r#"  local field_len = {len_expr}"#)?;
                // writeln!(
                //     writer,
                //     r#"field_values["{}"] = {{ start = i, len = field_len }}"#,
                //     name
                // )?;
                if let Some(size) = size {
                    writeln!(writer, r#"  for j=1,{size} do"#)?;
                } else {
                    writeln!(writer, r#"  for j=1,65536 do  -- Cap at 65536 to avoid infinite loop"#)?;
                }
                writeln!(writer, r#"    if j >= buffer:len() then break end"#)?;
                writeln!(
                    writer,
                    r#"    local subtree = tree:add({buffer_expr}, "{}")"#,
                    name
                )?;
                writeln!(
                    writer,
                    r#"    i = i + {}_dissect({buffer_expr}, pinfo, subtree)"#,
                    decl.name
                )?;
                writeln!(writer, "    i = i + field_len")?;
                writeln!(writer, "  end")?;
            }
            FieldDissectorInfo::Typedef { name, decl, len } => {
                let (len_expr, buffer_expr) = if let Some(len_expr) = len.to_lua_expr() {
                    (len_expr, "buffer(i, field_len)")
                } else {
                    ("0".into(), "buffer(i)")
                };
                writeln!(writer, r#"  local field_len = {len_expr}"#)?;
                // writeln!(
                //     writer,
                //     r#"field_values["{}"] = {{ start = i, len = field_len }}"#,
                //     name
                // )?;
                writeln!(
                    writer,
                    r#"  local subtree = tree:add({buffer_expr}, "{}")"#,
                    name
                )?;
                writeln!(
                    writer,
                    r#"  i = i + {}_dissect({buffer_expr}, pinfo, subtree)"#,
                    decl.name
                )?;
                // writeln!(writer, "i = i + field_len")?;
            }
        }
        Ok(())
    }
}

impl DissectorInfo for FieldDissectorInfo {
    fn collect_reachable_decls(&self, add_decl: &mut impl FnMut(DeclDissectorInfo)) {
        match self {
            FieldDissectorInfo::Scalar { .. } => {}
            FieldDissectorInfo::Typedef { decl, .. } | FieldDissectorInfo::Array { decl, .. } => {
                decl.collect_reachable_decls(add_decl);
            }
        }
    }
}

impl ToDissector for Field<analyzer::ast::Annotation> {
    type Info = Option<FieldDissectorInfo>;

    fn to_dissector_info(&self, ctx: &Context) -> Self::Info {
        debug!("Write field: {:?} {:?}", self, self.annot);
        match &self.desc {
            FieldDesc::Checksum { field_id } => todo!(),
            FieldDesc::Padding { size } => todo!(),
            FieldDesc::Size { field_id, width } => {
                let ftype = ftype_str(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: format!("{field_id}_size"),
                    abbr: ctx.full_field_name(&format!("{field_id}_size")),
                    ftype,
                    size: self.annot.size,
                    len: FieldLen::fixed(width / 8),
                    endian: ctx.endian,
                })
            }
            FieldDesc::Count { field_id, width } => todo!(),
            FieldDesc::ElementSize { field_id, width } => todo!(),
            FieldDesc::Body => todo!(),
            FieldDesc::Payload { size_modifier } => {
                let ftype = ftype_str(self.annot.size);
                let mut field_len = FieldLen::fixed(0);
                field_len.add_len_field(
                    "_payload__size".into(),
                    size_modifier
                        .as_ref()
                        .map(|s| s.parse::<usize>().unwrap())
                        .unwrap_or_default(),
                );
                Some(FieldDissectorInfo::Scalar {
                    name: String::from("_payload_"),
                    abbr: ctx.full_field_name("_payload_"),
                    ftype,
                    size: self.annot.size,
                    len: field_len,
                    endian: ctx.endian,
                })
            }
            FieldDesc::FixedScalar { width, value } => {
                let ftype = ftype_str(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: String::from("_fixed_"),
                    abbr: ctx.full_field_name("_fixed_"),
                    ftype,
                    size: self.annot.size,
                    len: FieldLen::fixed(width / 8),
                    endian: ctx.endian,
                })
            }
            FieldDesc::FixedEnum { enum_id, tag_id } => todo!(),
            FieldDesc::Reserved { width } => Some(FieldDissectorInfo::Scalar {
                name: String::from("_reserved_"),
                abbr: ctx.full_field_name("_reserved_"),
                ftype: "ftypes.NONE",
                size: self.annot.size,
                len: FieldLen::fixed(width / 8),
                endian: ctx.endian,
            }),
            FieldDesc::Array {
                id,
                width,
                type_id,
                size_modifier,
                size,
            } => type_id.as_ref().map(|type_id| FieldDissectorInfo::Array {
                name: id.clone(),
                decl: Box::new(
                    ctx.find_decl(type_id)
                        .expect("Unresolved typedef")
                        .to_dissector_info(&ctx.with_prefix(id)),
                ),
                len: match (width, size_modifier, size) {
                    (_, _, None) => FieldLen::Unbounded,
                    (Some(width), None, Some(size)) => FieldLen::fixed(width * size / 8),
                    (None, Some(size_modifier), Some(_size)) => {
                        let mut len = FieldLen::fixed(0);
                        len.add_len_field(format!("{id}_size"), str::parse(size_modifier).unwrap());
                        len
                    }
                    _ => unreachable!(),
                },
                size: *size,
            }),
            FieldDesc::Scalar { id, width } => {
                let ftype = ftype_str(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: String::from(id),
                    abbr: ctx.full_field_name(id),
                    ftype,
                    size: self.annot.size,
                    len: FieldLen::fixed(width / 8),
                    endian: ctx.endian,
                })
            }
            FieldDesc::Flag {
                id,
                optional_field_id,
                set_value,
            } => todo!(),
            FieldDesc::Typedef { id, type_id } => {
                let dissector_info = ctx
                    .find_decl(type_id)
                    .expect("Unresolved typedef")
                    .to_dissector_info(&ctx.with_prefix(id));
                let decl_len = dissector_info.decl_len();
                Some(FieldDissectorInfo::Typedef {
                    name: id.clone(),
                    decl: Box::new(dissector_info),
                    len: decl_len,
                })
            }
            FieldDesc::Group {
                group_id,
                constraints,
            } => todo!(),
        }
    }
}

pub fn ftype_str(size: Size) -> &'static str {
    match size {
        Size::Static(8) => "ftypes.UINT8",
        Size::Static(16) => "ftypes.UINT16",
        Size::Static(24) => "ftypes.UINT24",
        Size::Static(32) => "ftypes.UINT32",
        Size::Static(64) => "ftypes.UINT64",
        Size::Static(l) if l % 8 == 0 => "ftypes.BYTES",
        _ => "ftypes.NONE",
    }
}

/// Command line arguments for this tool.
#[derive(clap::Parser)]
struct Args {
    /// The PDL file to generate the Wireshark dissector from. See
    /// https://github.com/google/pdl/blob/main/doc/reference.md.
    pdl_file: String,
    /// The type in the PDL file to generate dissector for.
    ///
    /// Since a PDL file can contain multiple packet declarations, this
    /// specifies which packet the dissector should be generated for.
    packet_type: String,
}

fn get_desc_id<A: Annotation>(desc: &DeclDesc<A>) -> String {
    match desc {
        DeclDesc::Checksum { id, .. }
        | DeclDesc::CustomField { id, .. }
        | DeclDesc::Enum { id, .. }
        | DeclDesc::Packet { id, .. }
        | DeclDesc::Struct { id, .. }
        | DeclDesc::Group { id, .. } => id.clone(),
        DeclDesc::Test { .. } => todo!(),
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Args::parse();

    let mut sources = SourceDatabase::new();
    let file = pdl_compiler::parser::parse_file(&mut sources, &args.pdl_file)
        .map_err(|msg| anyhow!("{msg:?}"))?;
    let analyzed_file = analyzer::analyze(&file).map_err(|msg| anyhow!("{msg:?}"))?;
    let target_decl = analyzed_file
        .declarations
        .iter()
        .find(|decl| get_desc_id(&decl.desc) == args.packet_type);
    if let Some(decl) = target_decl {
        println!(
            r#"protocol = Proto("{decl_name}",  "{decl_name}")"#,
            decl_name = args.packet_type
        );
        println!(r#"protocol.fields = {{}}"#);
        let target_dissector_info = decl.to_dissector_info(&Context {
            prefix: vec![args.packet_type],
            file: analyzed_file.clone(),
            endian: analyzed_file.endianness.value,
        });
        let mut decls = Vec::new();
        target_dissector_info.collect_reachable_decls(&mut |v| decls.push(v));
        for decl in decls {
            decl.write_proto_fields(&mut std::io::stdout())?;
            println!(
                r#"for k,v in pairs({}_protocol_fields) do protocol.fields[k] = v end"#,
                decl.name
            );
            decl.write_dissect_fn(&mut std::io::stdout())?;
        }

        target_dissector_info.write_main_dissector(&mut std::io::stdout())?;

        println!(
            r#"
        local tcp_port = DissectorTable.get("tcp.port")
        tcp_port:add(8000, protocol)
        "#
        );
    } else {
        anyhow::bail!("Unable to find declaration {:?}", args.packet_type);
    }
    Ok(())
}
