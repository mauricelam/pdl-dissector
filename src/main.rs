#[cfg(test)]
mod fakes;

use anyhow::anyhow;
use clap::Parser;
use indoc::{formatdoc, writedoc};
use log::debug;
use pdl_compiler::{
    analyzer::{self, ast::Size, Scope},
    ast::{
        Annotation, Decl, DeclDesc, EndiannessValue, Field, FieldDesc, SourceDatabase, Tag,
        TagOther, TagRange, TagValue,
    },
};
use std::{fmt::Write, path::PathBuf};

#[derive(Clone, Debug)]
struct Context<'a> {
    scope: &'a Scope<'a, analyzer::ast::Annotation>,
}

impl Context<'_> {
    pub fn endian(&self) -> EndiannessValue {
        self.scope.file.endianness.value
    }
}

trait DeclExt {
    type Info;

    fn to_dissector_info(&self, ctx: &Context) -> Self::Info;
}

#[derive(Debug, Clone)]
pub enum DeclDissectorInfo {
    Sequence {
        name: String,
        fields: Vec<FieldDissectorInfo>,
        children: Vec<DeclDissectorInfo>,
    },
    Enum {
        name: String,
        values: Vec<Tag>,
        len: usize,
    },
}

impl DeclDissectorInfo {
    fn write_proto_fields(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        match self {
            DeclDissectorInfo::Sequence {
                name,
                fields,
                children,
            } => {
                let field_decls: Vec<(String, String)> = fields
                    .iter()
                    .filter_map(|f| f.field_declaration())
                    .collect();
                writeln!(writer, r#"function {name}_protocol_fields(fields, path)"#)?;
                for (name, decl) in field_decls {
                    writeln!(writer, r#"    fields[path .. ".{name}"] = {decl}"#)?;
                }
                for child in children {
                    let child_name = child.name();
                    writeln!(
                        writer,
                        r#"    {child_name}_protocol_fields(fields, path .. ".{child_name}")"#
                    )?;
                }
                writeln!(writer, r#"end"#)?;
            }
            DeclDissectorInfo::Enum {
                name,
                values,
                len: _,
            } => {
                writeln!(writer, r#"local {name}_enum = {{}}"#)?;
                for tag in values {
                    match tag {
                        Tag::Value(TagValue { id, loc: _, value }) => {
                            writeln!(writer, r#"{name}_enum[{value}] = "{id}""#)?;
                        }
                        Tag::Range(TagRange {
                            id: range_id,
                            loc: _,
                            range: _,
                            tags,
                        }) => {
                            for TagValue { id, loc: _, value } in tags {
                                writeln!(writer, r#"{name}_enum[{value}] = "{range_id}: {id}""#)?;
                            }
                        }
                        Tag::Other(TagOther { id, loc: _ }) => {
                            writeln!(
                                writer,
                                r#"setmetatable({name}_enum, {{ __index = function () return "{id}" end }})"#
                            )?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn write_main_dissector(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        match self {
            DeclDissectorInfo::Sequence {
                name,
                fields: _,
                children: _,
            } => {
                writedoc!(
                    writer,
                    r#"
                    function {name}_protocol.dissector(buffer, pinfo, tree)
                        pinfo.cols.protocol = "{name}"
                        local subtree = tree:add({name}_protocol, buffer(), "{name}")
                        {name}_dissect(buffer, pinfo, subtree, {name}_protocol.fields, "{name}")
                    end
                    {name}_protocol.fields = {{}}
                    {name}_protocol_fields({name}_protocol.fields, "{name}")
                    "#,
                )?;
            }
            DeclDissectorInfo::Enum { .. } => unreachable!(),
        }
        Ok(())
    }

    /// The length of this declaration, which is the sum of the lengths of all
    /// of its fields.
    pub fn decl_len(&self) -> RuntimeLenInfo {
        match self {
            DeclDissectorInfo::Sequence {
                name: _,
                fields,
                children: _,
            } => {
                let mut field_len = RuntimeLenInfo::fixed(0);
                for field in fields {
                    field_len.add(field.len());
                }
                field_len
            }
            DeclDissectorInfo::Enum {
                name: _,
                values: _,
                len,
            } => RuntimeLenInfo::fixed(*len),
        }
    }

    pub fn write_dissect_fn(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        match self {
            DeclDissectorInfo::Sequence {
                name,
                fields,
                children: _,
            } => {
                writedoc!(
                    writer,
                    r#"
                    -- {self:?}
                    function {name}_dissect(buffer, pinfo, tree, fields, path)
                        local i = 0
                        local field_values = {{}}
                    "#
                )?;
                for field in fields {
                    field.write_dissect_fn(writer)?;
                }
                writedoc!(
                    writer,
                    r#"
                        return i
                    end
                    "#
                )?;
            }
            DeclDissectorInfo::Enum { .. } => {}
        }
        Ok(())
    }

    fn name(&self) -> &str {
        match self {
            DeclDissectorInfo::Sequence { name, .. } => name,
            DeclDissectorInfo::Enum { name, .. } => name,
        }
    }
}

impl DeclExt for Decl<analyzer::ast::Annotation> {
    type Info = DeclDissectorInfo;

    fn to_dissector_info(&self, ctx: &Context) -> Self::Info {
        debug!("Write decl: {self:?}");
        match &self.desc {
            DeclDesc::Enum { id, tags, width } => DeclDissectorInfo::Enum {
                name: id.clone(),
                values: tags.clone(),
                len: width / 8,
            },
            DeclDesc::Checksum { id, .. }
            | DeclDesc::CustomField { id, .. }
            | DeclDesc::Packet { id, .. }
            | DeclDesc::Struct { id, .. }
            | DeclDesc::Group { id, .. } => {
                DeclDissectorInfo::Sequence {
                    name: id.clone(),
                    fields: self
                        .fields()
                        .filter_map(|field| field.to_dissector_info(ctx, self))
                        .collect(),
                    children: ctx
                        .scope
                        .iter_children(self)
                        .map(|child| child.to_dissector_info(ctx)) // TODO: the prefix will be wrong?
                        .collect::<Vec<_>>(),
                }
            }
            DeclDesc::Test {
                type_id,
                test_cases,
            } => unimplemented!(),
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
    pub fn to_lua_expr(&self) -> String {
        match self {
            RuntimeLenInfo::Bounded {
                referenced_fields,
                constant_factor,
            } => {
                let mut output_code = format!("sum_or_nil({constant_factor}");
                for field in referenced_fields {
                    write!(output_code, r#", field_values["{field}"]"#).unwrap();
                }
                write!(output_code, ")").unwrap();
                output_code
            }
            RuntimeLenInfo::Unbounded => "nil".into(),
        }
    }
}

trait FieldExt {
    fn to_dissector_info(
        &self,
        ctx: &Context,
        decl: &Decl<pdl_compiler::analyzer::ast::Annotation>,
    ) -> Option<FieldDissectorInfo>;
}

#[derive(Debug, Clone)]
pub enum FieldDissectorInfo {
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
        abbr: String,
        decl: Box<DeclDissectorInfo>,
        len: RuntimeLenInfo,
        endian: EndiannessValue,
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
            FieldDissectorInfo::Typedef {
                name,
                abbr,
                decl,
                len: _,
                endian: _,
            } => match &**decl {
                DeclDissectorInfo::Sequence { .. } => None,
                DeclDissectorInfo::Enum {
                    name: type_name,
                    values: _,
                    len,
                } => {
                    let ftype: &str = ftype_lua_expr(Size::Static(len * 8));
                    Some((
                        name.to_string(),
                        format!(r#"ProtoField.new("{name}", "{abbr}", {ftype}, {type_name}_enum)"#),
                    ))
                }
            },
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

    pub fn write_dissect_fn(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
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
                let len_expr = self.len().to_lua_expr();
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
                    -- {self:?}
                        local field_len = enforce_len_limit({len_expr}, buffer(i):len(), tree)
                        field_values["{name}"] = buffer(i, field_len):{buffer_value_function}()
                        {validate}
                        if field_len ~= 0 then
                            tree:{add_fn}(fields[path .. ".{name}"], buffer(i, field_len))
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
                let type_name = &decl.name();
                let size = size.unwrap_or(65536); // Cap at 65536 to avoid infinite loop
                writedoc!(
                    writer,
                    r#"
                    -- {self:?}
                        local size = field_values["{name}:count"]
                        if size == nil then
                            size = {size}
                        end
                        for j=1,size do
                            if i >= buffer:len() then break end
                            local subtree = tree:add(buffer(i), "{name}")
                            local dissected_len = {type_name}_dissect(buffer(i), pinfo, subtree, fields, path)
                            subtree:set_len(dissected_len)
                            i = i + dissected_len
                        end
                    "#,
                )?;
            }
            FieldDissectorInfo::Typedef {
                name,
                abbr: _,
                decl,
                len,
                endian,
            } => match &**decl {
                DeclDissectorInfo::Sequence {
                    name: type_name, ..
                } => {
                    let len_expr = len.to_lua_expr();
                    writedoc!(
                        writer,
                        r#"
                        -- {self:?}
                            local field_len = enforce_len_limit({len_expr}, buffer(i):len(), tree)
                            local subtree = tree:add(buffer(i, field_len), "{name}")
                            local dissected_len = {type_name}_dissect(buffer(i, field_len), pinfo, subtree, fields, path)
                            subtree:set_len(dissected_len)
                            i = i + dissected_len
                        "#,
                    )?;
                }
                DeclDissectorInfo::Enum {
                    name: type_name,
                    values,
                    len,
                } => {
                    let add_fn = match endian {
                        EndiannessValue::LittleEndian => "add_le",
                        EndiannessValue::BigEndian => "add",
                    };
                    let len_expr = self.len().to_lua_expr();
                    let buffer_value_function = match (endian, len) {
                        (EndiannessValue::BigEndian, 64) => "uint64",
                        (EndiannessValue::LittleEndian, 64) => "le_uint64",
                        (EndiannessValue::BigEndian, 32) => "uint",
                        (EndiannessValue::LittleEndian, 32) => "le_uint",
                        _ => "raw",
                    };
                    // let validate = validate_expr.as_ref().map(|validate_expr| {
                    //     formatdoc!(
                    //         r#"
                    //         if not (function (value) return {validate_expr} end)(field_values["{name}"]) then
                    //             tree:add_expert_info(PI_MALFORMED, PI_WARN, "Validation failed: Expected `{validate_escaped}`")
                    //         end
                    //         "#,
                    //         validate_escaped = validate_expr.replace('\\', "\\\\").replace('"', "\\\"")
                    //     )
                    // })
                    // .unwrap_or_default();
                    writedoc!(
                        writer,
                        r#"
                        -- {self:?}
                            local field_len = enforce_len_limit({len_expr}, buffer(i):len(), tree)
                            field_values["{name}"] = buffer(i, field_len):{buffer_value_function}()
                            if field_len ~= 0 then
                                tree:{add_fn}(fields[path .. ".{name}"], buffer(i, field_len))
                                i = i + field_len
                            end
                        "#,
                    )?;
                }
            },
        }
        Ok(())
    }
}

impl FieldExt for Field<analyzer::ast::Annotation> {
    fn to_dissector_info(
        &self,
        ctx: &Context,
        decl: &Decl<pdl_compiler::analyzer::ast::Annotation>,
    ) -> Option<FieldDissectorInfo> {
        debug!(
            "Write field: {:?}\nannot={:?}\ndecl={:?}",
            self, self.annot, decl
        );
        match &self.desc {
            FieldDesc::Checksum { field_id } => todo!(),
            FieldDesc::Padding { size } => Some(FieldDissectorInfo::Scalar {
                name: "Padding".into(),
                abbr: "padding".into(),
                ftype: "ftypes.BYTES",
                size: self.annot.size,
                len_bytes: RuntimeLenInfo::fixed(*size),
                endian: ctx.endian(),
                validate_expr: Some(r#"value == string.rep("\000", #value)"#.to_string()),
            }),
            FieldDesc::Size { field_id, width } => {
                for child_decl in ctx.scope.iter_children(decl) {
                    // Generate code for matching against constraints of the child
                }
                let ftype = ftype_lua_expr(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: format!("{field_id}:size"),
                    abbr: format!("{field_id}_size"),
                    ftype,
                    size: self.annot.size,
                    len_bytes: RuntimeLenInfo::fixed(width / 8),
                    endian: ctx.endian(),
                    validate_expr: None,
                })
            }
            FieldDesc::Count { field_id, width } => {
                let ftype = ftype_lua_expr(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: format!("{field_id}:count"),
                    abbr: format!("{field_id}_count"),
                    ftype,
                    size: self.annot.size,
                    len_bytes: RuntimeLenInfo::fixed(*width),
                    endian: ctx.endian(),
                    validate_expr: None,
                })
            }
            FieldDesc::ElementSize { field_id, width } => todo!(),
            FieldDesc::Body => {
                let ftype = ftype_lua_expr(self.annot.size);
                let mut field_len = RuntimeLenInfo::fixed(0);
                field_len.add_len_field("_body_:size".into(), 0);
                Some(FieldDissectorInfo::Scalar {
                    name: String::from("_body_"),
                    abbr: "_body_".into(),
                    ftype,
                    size: self.annot.size,
                    len_bytes: field_len,
                    endian: ctx.endian(),
                    validate_expr: None,
                })
            }
            FieldDesc::Payload { size_modifier } => {
                let ftype = ftype_lua_expr(self.annot.size);
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
                    abbr: "_payload_".into(),
                    ftype,
                    size: self.annot.size,
                    len_bytes: field_len,
                    endian: ctx.endian(),
                    validate_expr: None,
                })
            }
            FieldDesc::FixedScalar { width, value } => {
                let ftype = ftype_lua_expr(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: format!("Fixed value: {value}"),
                    abbr: "_fixed_".into(),
                    ftype,
                    size: self.annot.size,
                    len_bytes: RuntimeLenInfo::fixed(width / 8),
                    endian: ctx.endian(),
                    validate_expr: Some(format!("value == {value}")),
                })
            }
            FieldDesc::FixedEnum { enum_id, tag_id } => {
                let referenced_enum = ctx.scope.typedef[enum_id].to_dissector_info(ctx);
                let ftype = ftype_lua_expr(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: format!("Fixed value: {tag_id}"),
                    abbr: "_fixed_".into(),
                    ftype,
                    size: self.annot.size,
                    len_bytes: referenced_enum.decl_len(),
                    endian: ctx.endian(),
                    validate_expr: Some(format!("value == {tag_id}")),
                })
            }
            FieldDesc::Reserved { width } => Some(FieldDissectorInfo::Scalar {
                name: String::from("_reserved_"),
                abbr: "_reserved_".into(),
                ftype: "ftypes.NONE",
                size: self.annot.size,
                len_bytes: RuntimeLenInfo::fixed(width / 8),
                endian: ctx.endian(),
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
                    {
                        let this = &ctx;
                        this.scope.typedef.get(type_id).copied()
                    }
                    .expect("Unresolved typedef")
                    .to_dissector_info(ctx),
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
                let ftype = ftype_lua_expr(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    name: String::from(id),
                    abbr: id.into(),
                    ftype,
                    size: self.annot.size,
                    len_bytes: RuntimeLenInfo::fixed(width / 8),
                    endian: ctx.endian(),
                    validate_expr: None,
                })
            }
            FieldDesc::Flag {
                id,
                optional_field_id,
                set_value,
            } => todo!(),
            FieldDesc::Typedef { id, type_id } => {
                let dissector_info = {
                    let this = &ctx;
                    this.scope.typedef.get(type_id).copied()
                }
                .expect("Unresolved typedef")
                .to_dissector_info(ctx);
                let decl_len = dissector_info.decl_len();
                Some(FieldDissectorInfo::Typedef {
                    name: id.into(),
                    abbr: id.into(),
                    decl: Box::new(dissector_info),
                    len: decl_len,
                    endian: ctx.scope.file.endianness.value,
                })
            }
            FieldDesc::Group {
                group_id,
                constraints,
            } => todo!(),
        }
    }
}

pub fn ftype_lua_expr(size: Size) -> &'static str {
    match size {
        Size::Static(8) => "ftypes.UINT8",
        Size::Static(16) => "ftypes.UINT16",
        Size::Static(24) => "ftypes.UINT24",
        Size::Static(32) => "ftypes.UINT32",
        Size::Static(64) => "ftypes.UINT64",
        Size::Static(l) if l % 8 == 0 => "ftypes.BYTES",
        _ => "ftypes.BYTES",
    }
}

/// Command line arguments for this tool.
#[derive(clap::Parser)]
struct Args {
    /// The PDL file to generate the Wireshark dissector from. See
    /// https://github.com/google/pdl/blob/main/doc/reference.md.
    pdl_file: PathBuf,
    /// The type in the PDL file to generate dissector for.
    ///
    /// Since a PDL file can contain multiple packet declarations, this
    /// specifies which packet the dissector should be generated for.
    target_packets: Vec<String>,
}

fn get_desc_id<A: Annotation>(desc: &DeclDesc<A>) -> Option<String> {
    match desc {
        DeclDesc::Checksum { id, .. }
        | DeclDesc::CustomField { id, .. }
        | DeclDesc::Enum { id, .. }
        | DeclDesc::Packet { id, .. }
        | DeclDesc::Struct { id, .. }
        | DeclDesc::Group { id, .. } => Some(id.clone()),
        DeclDesc::Test { .. } => None,
    }
}

fn generate_for_decl(
    decl_name: &str,
    decl: &Decl<pdl_compiler::analyzer::ast::Annotation>,
    scope: &Scope<pdl_compiler::analyzer::ast::Annotation>,
    writer: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let target_dissector_info = decl.to_dissector_info(&Context { scope });

    writeln!(
        writer,
        r#"{decl_name}_protocol = Proto("{decl_name}",  "{decl_name}")"#,
    )?;

    target_dissector_info.write_main_dissector(writer)?;

    writedoc!(
        writer,
        r#"
        local tcp_port = DissectorTable.get("tcp.port")
        tcp_port:add(8000, {decl_name}_protocol)
        "#
    )?;
    Ok(())
}

fn run(args: Args, writer: &mut impl std::io::Write) -> anyhow::Result<()> {
    let _ = env_logger::try_init();

    let mut sources = SourceDatabase::new();
    let file = pdl_compiler::parser::parse_file(
        &mut sources,
        args.pdl_file
            .to_str()
            .expect("pdl_file path should be a valid string"),
    )
    .map_err(|msg| anyhow!("{msg:?}"))?;
    let analyzed_file = analyzer::analyze(&file).map_err(|msg| anyhow!("{msg:?}"))?;
    let scope = Scope::new(&analyzed_file).map_err(|msg| anyhow!("{msg:?}"))?;
    assert!(!args.target_packets.is_empty());
    for target_packet in args.target_packets {
        for decl in analyzed_file.declarations.iter() {
            let decl_dissector_info = decl.to_dissector_info(&Context { scope: &scope });
            decl_dissector_info.write_proto_fields(writer)?;
            decl_dissector_info.write_dissect_fn(writer)?;
        }
        if target_packet == "_all_" {
            for decl in analyzed_file.declarations.iter() {
                if matches!(decl.desc, DeclDesc::Packet { .. }) {
                    generate_for_decl(&target_packet, decl, &scope, writer)?;
                }
            }
        } else {
            let target_decl = analyzed_file.declarations.iter().find(|decl| {
                get_desc_id(&decl.desc)
                    .map(|id| id == target_packet)
                    .unwrap_or(false)
            });
            if let Some(decl) = target_decl {
                generate_for_decl(&target_packet, decl, &scope, writer)?;
            } else {
                anyhow::bail!("Unable to find declaration {:?}", target_packet);
            }
        }
    }
    writedoc!(
        writer,
        r#"
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
        "#
    )?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    run(args, &mut std::io::stdout())
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use std::{io::BufWriter, path::PathBuf};

    use crate::{fakes::wireshark_lua, run, Args};

    #[test]
    fn test_pcap() {
        let args = Args {
            pdl_file: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pcap.pdl"),
            target_packets: vec!["PcapFile".into()],
        };
        let mut writer = BufWriter::new(Vec::new());
        run(args, &mut writer).unwrap();

        pretty_assertions::assert_str_eq!(
            include_str!("../tests/pcap_golden.lua"),
            std::str::from_utf8(writer.buffer()).unwrap(),
        );
    }

    #[test]
    fn test_bluetooth_hci() -> anyhow::Result<()> {
        let args = Args {
            pdl_file: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bluetooth_hci.pdl"),
            target_packets: vec!["_all_".into()],
        };
        let mut writer = BufWriter::new(Vec::new());
        run(args, &mut writer).unwrap();

        let lua = wireshark_lua()?;
        lua.load(writer.buffer()).exec()?;
        Ok(())
    }

    #[test]
    fn test_le() -> anyhow::Result<()> {
        let args = Args {
            pdl_file: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_le.pdl"),
            target_packets: vec!["TopLevel".into()],
        };
        let mut writer = BufWriter::new(Vec::new());
        run(args, &mut writer).unwrap();

        let lua = wireshark_lua()?;
        lua.load(writer.buffer()).exec()?;
        let bytes = hex!("0000");
        lua.load(mlua::chunk! { TopLevel_protocol.dissector(Tvb($bytes), new_pinfo(), Tree()) })
            .exec()?;
        Ok(())
    }
}
