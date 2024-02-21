use anyhow::anyhow;
use clap::Parser;
use indoc::{formatdoc, printdoc, writedoc};
use log::debug;
use pdl_compiler::{
    analyzer::{self, ast::Size},
    ast::{Annotation, Decl, DeclDesc, EndiannessValue, Field, FieldDesc, File, SourceDatabase},
};
use std::fmt::Write;

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
            writeln!(writer, r#"    ["{name}"] = {decl},"#)?;
        }
        writeln!(writer, r#"}}"#)?;
        Ok(())
    }

    pub fn write_main_dissector(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        let type_name = &self.name;
        writedoc!(
            writer,
            r#"
            function protocol.dissector(buffer, pinfo, tree)
                pinfo.cols.protocol = protocol.name
                local subtree = tree:add(protocol, buffer(), "{type_name}")
                {type_name}_dissect(buffer, pinfo, subtree)
            end
            "#,
        )?;
        Ok(())
    }

    /// The length of this declaration, which is the sum of the lengths of all
    /// of its fields.
    pub fn decl_len(&self) -> RuntimeLenInfo {
        let mut field_len = RuntimeLenInfo::fixed(0);
        for field in &self.fields {
            field_len.add(field.len());
        }
        field_len
    }

    pub fn write_dissect_fn(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        let type_name = &self.name;
        writedoc!(
            writer,
            r#"
            function {type_name}_dissect(buffer, pinfo, tree)
                local i = 0
                local field_values = {{}}
            "#
        )?;
        let field_table = format!("{}_protocol_fields", self.name);
        for field in &self.fields {
            field.write_dissect_fn(writer, &field_table)?;
        }
        writedoc!(
            writer,
            r#"
                return i
            end
            "#
        )?;
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
    }
}

/// Representation of length info that is resolvable at runtime. The unit of
/// this value depends on context. For example, it can either represent the
/// number of bytes, or the number of times a field is repeated.
#[derive(Debug, Clone)]
pub enum RuntimeLenInfo {
    /// The field length is bounded. The resulting length is given by
    /// `SUM(valueof(referenced_fields)) + constant_factor`.
    Bounded {
        referenced_fields: Vec<String>,
        constant_factor: usize,
    },
    /// The field length is unbounded, e.g. if this is an array without a fixed
    /// size.
    Unbounded,
}

impl RuntimeLenInfo {
    pub fn fixed(size: usize) -> Self {
        Self::Bounded {
            referenced_fields: Vec::new(),
            constant_factor: size,
        }
    }

    pub fn add_len_field(&mut self, field: String, modifier: usize) {
        match self {
            RuntimeLenInfo::Bounded {
                referenced_fields,
                constant_factor,
            } => {
                *constant_factor += modifier;
                referenced_fields.push(field);
            }
            RuntimeLenInfo::Unbounded => *self = RuntimeLenInfo::Unbounded,
        }
    }

    pub fn add(&mut self, other: &RuntimeLenInfo) {
        *self = match (&self, other) {
            (
                RuntimeLenInfo::Bounded {
                    referenced_fields,
                    constant_factor,
                },
                RuntimeLenInfo::Bounded {
                    referenced_fields: other_referenced_fields,
                    constant_factor: other_constant_factor,
                },
            ) => RuntimeLenInfo::Bounded {
                referenced_fields: [referenced_fields.as_slice(), &other_referenced_fields]
                    .concat(),
                constant_factor: constant_factor + other_constant_factor,
            },
            _ => RuntimeLenInfo::Unbounded,
        }
    }

    /// Prints the lua code to calculate the buffer for this len. Assumes the
    /// following lua variables are in scope:
    ///
    /// Returns an option that is `None` if this length is unbounded, otherwise
    /// returns a lua expression for the field length.
    pub fn to_lua_expr(&self) -> Option<String> {
        match self {
            RuntimeLenInfo::Bounded {
                referenced_fields,
                constant_factor,
            } => {
                let mut output_code = constant_factor.to_string();
                for field in referenced_fields {
                    write!(output_code, r#" + field_values["{field}"]"#).unwrap();
                }
                Some(output_code)
            }
            RuntimeLenInfo::Unbounded => None,
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
        /// The number of times this field can be repeated.
        size: Size,
        /// The number of bytes this field takes before repetition.
        len_bytes: RuntimeLenInfo,
        endian: EndiannessValue,
        /// A lua-expression that yields a boolean value. If the boolean result
        /// is false, a warning will be shown in the dissected info. `value` is
        /// a variable that can be used to get the value of this field.
        validate_expr: Option<String>,
    },
    Typedef {
        name: String,
        decl: Box<DeclDissectorInfo>,
        len: RuntimeLenInfo,
    },
    Array {
        name: String,
        decl: Box<DeclDissectorInfo>,
        len: RuntimeLenInfo,
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

    pub fn len(&self) -> &RuntimeLenInfo {
        match self {
            FieldDissectorInfo::Scalar { len_bytes: len, .. } => len,
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
                name,
                endian,
                size,
                validate_expr,
                ..
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
                let buffer_value_function = match (endian, size) {
                    (EndiannessValue::BigEndian, Size::Static(64)) => "uint64",
                    (EndiannessValue::LittleEndian, Size::Static(64)) => "le_uint64",
                    (EndiannessValue::BigEndian, Size::Static(32)) => "uint",
                    (EndiannessValue::LittleEndian, Size::Static(32)) => "le_uint",
                    (EndiannessValue::BigEndian, _) => "raw",
                    (EndiannessValue::LittleEndian, _) => "raw",
                };
                let validate = validate_expr.as_ref().map(|validate_expr| {
                    formatdoc!(
                        r#"
                        if not (function (value) return {validate_expr} end)(field_values["{name}"]) then
                            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Validation failed: Expected `{validate_escaped}`")
                        end
                        "#,
                        validate_escaped = validate_expr.replace('\\', "\\\\").replace('"', "\\\"")
                    )
                })
                .unwrap_or_default();
                writedoc!(
                    writer,
                    r#"
                    --
                        local field_len = enforce_len_limit({len_expr}, buffer(i):len(), tree)
                        field_values["{name}"] = {buffer_expr}:{buffer_value_function}()
                        {validate}
                        if field_len ~= 0 then
                            tree:{add_fn}({field_table}["{name}"], {buffer_expr})
                            i = i + field_len
                        end
                    "#,
                )?;
            }
            FieldDissectorInfo::Array {
                name,
                decl,
                len: _,
                size,
            } => {
                let type_name = &decl.name;
                let size = size.unwrap_or(65536); // Cap at 65536 to avoid infinite loop
                writedoc!(
                    writer,
                    r#"
                    --
                        local size = field_values["{name}:count"]
                        if size == nil then
                            size = {size}
                        end
                        for j=1,size do
                            if i >= buffer:len() then break end
                            local subtree = tree:add(buffer(i), "{name}")
                            local dissected_len = {type_name}_dissect(buffer(i), pinfo, subtree)
                            subtree:set_len(dissected_len)
                            i = i + dissected_len
                        end
                    "#,
                )?;
            }
            FieldDissectorInfo::Typedef { name, decl, len } => {
                let type_name = &decl.name;
                let (len_expr, buffer_expr) = if let Some(len_expr) = len.to_lua_expr() {
                    (len_expr, "buffer(i, field_len)")
                } else {
                    ("0".into(), "buffer(i)")
                };
                writedoc!(
                    writer,
                    r#"
                    --
                        local field_len = {len_expr}
                        local subtree = tree:add({buffer_expr}, "{name}")
                        local dissected_len = {type_name}_dissect({buffer_expr}, pinfo, subtree)
                        subtree:set_len(dissected_len)
                        i = i + dissected_len
                    "#,
                )?;
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
            FieldDesc::Padding { size } => {
                Some(FieldDissectorInfo::Scalar {
                    name: "Padding".into(),
                    abbr: ctx.full_field_name("_fixed_"),
                    ftype: "ftypes.BYTES",
                    size: self.annot.size,
                    len_bytes: RuntimeLenInfo::fixed(*size),
                    endian: ctx.endian,
                    validate_expr: Some(r#"value == string.rep("\000", #value)"#.to_string()),
                })
            },
            FieldDesc::Size { field_id, width } => {
                let ftype = ftype_str(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: format!("{field_id}:size"),
                    abbr: ctx.full_field_name(&format!("{field_id}_size")),
                    ftype,
                    size: self.annot.size,
                    len_bytes: RuntimeLenInfo::fixed(width / 8),
                    endian: ctx.endian,
                    validate_expr: None,
                })
            }
            FieldDesc::Count { field_id, width } => {
                let ftype = ftype_str(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: format!("{field_id}:count"),
                    abbr: ctx.full_field_name(&format!("{field_id}_count")),
                    ftype,
                    size: self.annot.size,
                    len_bytes: RuntimeLenInfo::fixed(*width),
                    endian: ctx.endian,
                    validate_expr: None,
                })
            },
            FieldDesc::ElementSize { field_id, width } => todo!(),
            FieldDesc::Body => {
                let ftype = ftype_str(self.annot.size);
                let mut field_len = RuntimeLenInfo::fixed(0);
                field_len.add_len_field("_body_:size".into(), 0);
                Some(FieldDissectorInfo::Scalar {
                    name: String::from("_body_"),
                    abbr: ctx.full_field_name("_body_"),
                    ftype,
                    size: self.annot.size,
                    len_bytes: field_len,
                    endian: ctx.endian,
                    validate_expr: None,
                })
            }
            FieldDesc::Payload { size_modifier } => {
                let ftype = ftype_str(self.annot.size);
                let mut field_len = RuntimeLenInfo::fixed(0);
                field_len.add_len_field(
                    "_payload_:size".into(),
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
                    len_bytes: field_len,
                    endian: ctx.endian,
                    validate_expr: None,
                })
            }
            FieldDesc::FixedScalar { width, value } => {
                let ftype = ftype_str(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: format!("Fixed value: {value}"),
                    abbr: ctx.full_field_name("_fixed_"),
                    ftype,
                    size: self.annot.size,
                    len_bytes: RuntimeLenInfo::fixed(width / 8),
                    endian: ctx.endian,
                    validate_expr: Some(format!("value == {value}")),
                })
            }
            FieldDesc::FixedEnum { enum_id, tag_id } => todo!(),
            FieldDesc::Reserved { width } => Some(FieldDissectorInfo::Scalar {
                name: String::from("_reserved_"),
                abbr: ctx.full_field_name("_reserved_"),
                ftype: "ftypes.NONE",
                size: self.annot.size,
                len_bytes: RuntimeLenInfo::fixed(width / 8),
                endian: ctx.endian,
                validate_expr: Some("value == 0".into()),
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
                    (Some(width), None, Some(size)) => RuntimeLenInfo::fixed(width * size / 8),
                    (None, Some(size_modifier), Some(_size)) => {
                        let mut len = RuntimeLenInfo::fixed(0);
                        len.add_len_field(format!("{id}:size"), str::parse(size_modifier).unwrap());
                        len
                    }
                    _ => RuntimeLenInfo::Unbounded,
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
                    len_bytes: RuntimeLenInfo::fixed(width / 8),
                    endian: ctx.endian,
                    validate_expr: None,
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
    target_packets: Vec<String>,
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
    assert!(!args.target_packets.is_empty());
    for target_packet in args.target_packets {
        let target_decl = analyzed_file
            .declarations
            .iter()
            .find(|decl| get_desc_id(&decl.desc) == target_packet);
        if let Some(decl) = target_decl {
            println!(
                r#"protocol = Proto("{decl_name}",  "{decl_name}")"#,
                decl_name = target_packet
            );
            println!(r#"protocol.fields = {{}}"#);
            let target_dissector_info = decl.to_dissector_info(&Context {
                prefix: vec![target_packet],
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

            printdoc!(
                r#"
                local tcp_port = DissectorTable.get("tcp.port")
                tcp_port:add(8000, protocol)
                "#
            );
        } else {
            anyhow::bail!("Unable to find declaration {:?}", target_packet);
        }
    }
    printdoc!(
        r#"
        -- Utils section

        function enforce_len_limit(num, limit, tree)
            if num > limit then
                tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Expected " .. num .. " bytes, but only " .. limit .. " bytes remaining")
                return limit
            end
            return num
        end

        -- End Utils section
        "#
    );
    Ok(())
}
