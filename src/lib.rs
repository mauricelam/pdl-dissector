#[cfg(test)]
mod fakes;
mod len_info;
mod utils;

use anyhow::anyhow;
use indoc::{formatdoc, writedoc};
use len_info::RuntimeLenInfo;
use log::{debug, info};
use pdl_compiler::{
    analyzer::{self, Scope},
    ast::{
        Annotation, Constraint, Decl, DeclDesc, EndiannessValue, Field, FieldDesc, SourceDatabase,
        Tag, TagOther, TagRange, TagValue,
    },
};
use std::{fmt::Write, path::PathBuf};
use utils::buffer_value_lua_function;

use crate::{len_info::ByteLen, utils::ftype_lua_expr};

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
    fn to_dissector_info(&self, ctx: &Context) -> DeclDissectorInfo;
}

#[derive(Debug, Clone)]
pub enum DeclDissectorInfo {
    Sequence {
        name: String,
        fields: Vec<FieldDissectorInfo>,
        children: Vec<DeclDissectorInfo>,
        constraints: Vec<ConstraintDissectorInfo>,
    },
    Enum {
        name: String,
        values: Vec<Tag>,
        len: ByteLen,
    },
}

impl DeclDissectorInfo {
    fn write_proto_fields(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        match self {
            DeclDissectorInfo::Sequence {
                name,
                fields,
                children,
                constraints: _,
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
                writeln!(writer, r#"local {name}_enum_range = {{}}"#)?;
                writeln!(writer, r#"local {name}_enum_matcher = {{}}"#)?;
                for tag in values {
                    match tag {
                        Tag::Value(TagValue { id, loc: _, value }) => {
                            writeln!(writer, r#"{name}_enum[{value}] = "{id}""#)?;
                            writeln!(
                                writer,
                                r#"table.insert({name}_enum_range, {{{value}, {value}, "{id}"}})"#
                            )?;
                            writeln!(
                                writer,
                                r#"{name}_enum_matcher["{id}"] = function(v) return v == {value} end"#
                            )?;
                        }
                        Tag::Range(TagRange {
                            id: range_id,
                            loc: _,
                            range,
                            tags,
                        }) => {
                            for TagValue { id, loc: _, value } in tags {
                                writeln!(writer, r#"{name}_enum[{value}] = "{range_id}: {id}""#)?;
                                writeln!(
                                    writer,
                                    r#"table.insert({name}_enum_range, {{{value}, {value}, "{range_id}: {id}"}})"#
                                )?;
                                writeln!(
                                    writer,
                                    r#"{name}_enum_matcher["{id}"] = function(v) return v == {value} end"#
                                )?;
                            }
                            let range_start = range.start();
                            let range_end = range.end();
                            writeln!(
                                writer,
                                r#"{name}_enum_matcher["{range_id}"] = function(v) return {range_start} <= v and v <= {range_end} end"#
                            )?;
                            writeln!(
                                writer,
                                r#"table.insert({name}_enum_range, {{{range_start}, {range_end}, "{range_id}"}})"#
                            )?;
                        }
                        Tag::Other(TagOther { id, loc: _ }) => {
                            writeln!(
                                writer,
                                r#"setmetatable({name}_enum, {{ __index = function () return "{id}" end }})"#
                            )?;
                            writeln!(
                                writer,
                                // 2^1024 ought to be big enough for anybody
                                r#"table.insert({name}_enum_range, {{0, 2^1024, "{id}"}})"#
                            )?;
                            writedoc!(
                                writer,
                                r#"
                                {name}_enum_matcher["{id}"] = function(v)
                                    for k,matcher in ipairs({name}_enum_matcher) do
                                        if k ~= "{id}" then
                                            if matcher(v) then
                                                return false
                                            end
                                        end
                                    end
                                    return true
                                end
                                "#
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
            DeclDissectorInfo::Sequence { name, .. } => {
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
            DeclDissectorInfo::Sequence { fields, .. } => {
                let mut field_len = RuntimeLenInfo::empty();
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
                constraints,
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
                if !constraints.is_empty() {
                    let constraints_lua = constraints
                        .iter()
                        .map(|c| c.to_lua_expr())
                        .collect::<Vec<_>>()
                        .join(" and ");
                    writedoc!(
                        writer,
                        r#"
                        function {name}_match_constraints(field_values)
                            return {constraints_lua}
                        end
                        "#
                    )?;
                }
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
    fn to_dissector_info(&self, ctx: &Context) -> DeclDissectorInfo {
        debug!("Write decl: {self:?}");
        match &self.desc {
            DeclDesc::Enum { id, tags, width } => {
                assert!(width % 8 == 0, "Unaligned field lengths are not supported");
                DeclDissectorInfo::Enum {
                    name: id.clone(),
                    values: tags.clone(),
                    len: ByteLen::from_bits(*width),
                }
            }
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
                    constraints: self
                        .constraints()
                        .map(|constraint| constraint.to_dissector_info(ctx.scope, self))
                        .collect::<Vec<_>>(),
                }
            }
            DeclDesc::Test { .. } => unimplemented!(),
        }
    }
}

trait ConstraintExt {
    fn to_dissector_info(
        &self,
        scope: &Scope,
        decl: &Decl<analyzer::ast::Annotation>,
    ) -> ConstraintDissectorInfo;
}

impl ConstraintExt for Constraint {
    fn to_dissector_info(
        &self,
        scope: &Scope,
        decl: &Decl<analyzer::ast::Annotation>,
    ) -> ConstraintDissectorInfo {
        match self {
            Constraint {
                id,
                loc: _,
                value: Some(v),
                tag_id: None,
            } => ConstraintDissectorInfo::ValueMatch {
                field: id.clone(),
                value: *v,
            },
            Constraint {
                id,
                loc: _,
                value: None,
                tag_id: Some(enum_tag),
            } => ConstraintDissectorInfo::EnumMatch {
                field: id.clone(),
                enum_type: scope
                    .get_parent(decl)
                    .unwrap()
                    .fields()
                    .find(|f| {
                        info!("Constraint match {id:?} vs {f:?}");
                        f.id() == Some(id)
                    })
                    .map(|f| match &f.desc {
                        FieldDesc::Typedef { id: _, type_id } => type_id.clone(),
                        _ => unreachable!(),
                    })
                    .unwrap(),
                enum_value: enum_tag.clone(),
            },
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ConstraintDissectorInfo {
    EnumMatch {
        field: String,
        enum_type: String,
        enum_value: String,
    },
    ValueMatch {
        field: String,
        value: usize,
    },
}

impl ConstraintDissectorInfo {
    pub fn to_lua_expr(&self) -> String {
        match self {
            ConstraintDissectorInfo::EnumMatch {
                field,
                enum_type,
                enum_value,
            } => {
                format!(r#"{enum_type}_enum_matcher["{enum_value}"](field_values["{field}"])"#)
            }
            ConstraintDissectorInfo::ValueMatch { field, value } => {
                format!(r#"field_values["{field}"] == {value}"#)
            }
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
        /// The number of bytes this field takes before repetition.
        len_bytes: RuntimeLenInfo,
        endian: EndiannessValue,
        /// A lua-expression that yields a boolean value. If the boolean result
        /// is false, a warning will be shown in the dissected info. `value` is
        /// a variable that can be used to get the value of this field.
        validate_expr: Option<String>,
    },
    Payload {
        /// Actual name of the field (the string that appears in the tree).
        name: String,
        /// Filter name of the field (the string that is used in filters).
        abbr: String,
        ftype: &'static str,
        /// The number of bytes this field takes before repetition.
        len_bytes: RuntimeLenInfo,
        endian: EndiannessValue,
        children: Vec<String>,
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
        /// Length of one item in the array.
        len: RuntimeLenInfo,
        /// Size of the array, or `None` if the array is unbounded
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
            }
            | FieldDissectorInfo::Payload {
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
                    let ftype: &str = ftype_lua_expr(RuntimeLenInfo::fixed(*len));
                    Some((
                        name.to_string(),
                        format!(
                            r#"ProtoField.new("{name}", "{abbr}", {ftype}, {type_name}_enum_range, base.RANGE_STRING)"#
                        ),
                    ))
                }
            },
            FieldDissectorInfo::Array { .. } => None,
        }
    }

    pub fn len(&self) -> &RuntimeLenInfo {
        match self {
            FieldDissectorInfo::Scalar { len_bytes: len, .. } => len,
            FieldDissectorInfo::Payload { len_bytes: len, .. } => len,
            FieldDissectorInfo::Typedef { len, .. } => len,
            FieldDissectorInfo::Array { len, .. } => len,
        }
    }

    pub fn write_dissect_fn(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        match self {
            FieldDissectorInfo::Scalar {
                name,
                endian,
                validate_expr,
                len_bytes,
                ..
            } => {
                let add_fn = match endian {
                    EndiannessValue::LittleEndian => "add_le",
                    EndiannessValue::BigEndian => "add",
                };
                let len_expr = self.len().to_lua_expr();
                let buffer_value_function = buffer_value_lua_function(*endian, len_bytes);
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
                        field_values["{name}"] = buffer(i, field_len):{buffer_value_function}
                        {validate}
                        if field_len ~= 0 then
                            tree:{add_fn}(fields[path .. ".{name}"], buffer(i, field_len))
                            i = i + field_len
                        end
                    "#,
                )?;
            }
            FieldDissectorInfo::Payload {
                name,
                endian,
                len_bytes,
                children,
                ..
            } => {
                let mut match_children = String::new();
                for child_name in children {
                    // TODO: Create a subtree
                    writedoc!(
                        match_children,
                        r#"
                        --
                                elseif {child_name}_match_constraints(field_values) then
                                    local dissected_len = {child_name}_dissect(buffer(i, field_len), pinfo, tree, fields, path .. ".{child_name}")
                                    i = i + dissected_len
                        "#
                    )
                    .unwrap();
                }
                let add_fn = match endian {
                    EndiannessValue::LittleEndian => "add_le",
                    EndiannessValue::BigEndian => "add",
                };
                let len_expr = self.len().to_lua_expr();
                let buffer_value_function = buffer_value_lua_function(*endian, len_bytes);
                writedoc!(
                    writer,
                    r#"
                    -- {self:?}
                        local field_len = enforce_len_limit({len_expr}, buffer(i):len(), tree)
                        field_values["{name}"] = buffer(i, field_len):{buffer_value_function}
                        if field_len ~= 0 then
                            if false then -- Just to make the following generated code more uniform
                            {match_children}
                            else
                                tree:{add_fn}(fields[path .. ".{name}"], buffer(i, field_len))
                                i = i + field_len
                            end
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
                    let buffer_value_function =
                        buffer_value_lua_function(*endian, &RuntimeLenInfo::fixed(*len));
                    writedoc!(
                        writer,
                        r#"
                        -- {self:?}
                            local field_len = enforce_len_limit({len_expr}, buffer(i):len(), tree)
                            field_values["{name}"] = buffer(i, field_len):{buffer_value_function}
                            if {type_name}_enum[field_values["{name}"]] == nil then
                                tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values["{name}"])
                            end
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
                len_bytes: RuntimeLenInfo::fixed(ByteLen(*size)),
                endian: ctx.endian(),
                validate_expr: Some(r#"value == string.rep("\000", #value)"#.to_string()),
            }),
            FieldDesc::Size { field_id, width } => {
                let ftype = ftype_lua_expr(self.annot.size.into());
                Some(FieldDissectorInfo::Scalar {
                    name: format!("{field_id}:size"),
                    abbr: format!("{field_id}_size"),
                    ftype,
                    len_bytes: RuntimeLenInfo::fixed(ByteLen::from_bits(*width)),
                    endian: ctx.endian(),
                    validate_expr: None,
                })
            }
            FieldDesc::Count { field_id, width } => {
                let ftype = ftype_lua_expr(self.annot.size.into());
                Some(FieldDissectorInfo::Scalar {
                    name: format!("{field_id}:count"),
                    abbr: format!("{field_id}_count"),
                    ftype,
                    len_bytes: RuntimeLenInfo::fixed(ByteLen(*width)),
                    endian: ctx.endian(),
                    validate_expr: None,
                })
            }
            FieldDesc::ElementSize { field_id, width } => todo!(),
            FieldDesc::Body => {
                let children = ctx
                    .scope
                    .iter_children(decl)
                    .filter_map(|child_decl| child_decl.id().map(|c| c.to_string()))
                    .collect::<Vec<_>>();
                let ftype = ftype_lua_expr(self.annot.size.into());
                let mut field_len = RuntimeLenInfo::empty();
                field_len.add_len_field("_body_:size".into(), ByteLen(0));
                Some(FieldDissectorInfo::Payload {
                    name: String::from("_body_"),
                    abbr: "_body_".into(),
                    ftype,
                    len_bytes: field_len,
                    endian: ctx.endian(),
                    children,
                })
            }
            FieldDesc::Payload { size_modifier } => {
                for child_decl in ctx.scope.iter_children(decl) {
                    // Generate code for matching against constraints of the child
                }
                let ftype = ftype_lua_expr(self.annot.size.into());
                let mut field_len = RuntimeLenInfo::empty();
                field_len.add_len_field(
                    "_payload_:size".into(),
                    size_modifier
                        .as_ref()
                        .map(|s| ByteLen(s.parse::<usize>().unwrap()))
                        .unwrap_or_default(),
                );
                Some(FieldDissectorInfo::Payload {
                    name: String::from("_payload_"),
                    abbr: "_payload_".into(),
                    ftype,
                    len_bytes: field_len,
                    endian: ctx.endian(),
                    children: vec![],
                })
            }
            FieldDesc::FixedScalar { width, value } => {
                let ftype = ftype_lua_expr(self.annot.size.into());
                Some(FieldDissectorInfo::Scalar {
                    name: format!("Fixed value: {value}"),
                    abbr: "_fixed_".into(),
                    ftype,
                    len_bytes: RuntimeLenInfo::fixed(ByteLen::from_bits(*width)),
                    endian: ctx.endian(),
                    validate_expr: Some(format!("value == {value}")),
                })
            }
            FieldDesc::FixedEnum { enum_id, tag_id } => {
                let referenced_enum = ctx.scope.typedef[enum_id].to_dissector_info(ctx);
                let ftype = ftype_lua_expr(self.annot.size.into());
                Some(FieldDissectorInfo::Scalar {
                    name: format!("Fixed value: {tag_id}"),
                    abbr: "_fixed_".into(),
                    ftype,
                    len_bytes: referenced_enum.decl_len(),
                    endian: ctx.endian(),
                    validate_expr: Some(format!("value == {tag_id}")),
                })
            }
            FieldDesc::Reserved { width } => Some(FieldDissectorInfo::Scalar {
                name: String::from("_reserved_"),
                abbr: "_reserved_".into(),
                ftype: "ftypes.NONE",
                len_bytes: RuntimeLenInfo::fixed(ByteLen::from_bits(*width)),
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
                    (Some(width), None, Some(size)) => {
                        RuntimeLenInfo::fixed(ByteLen::from_bits(width * size))
                    }
                    (None, Some(size_modifier), Some(_size)) => {
                        let mut len = RuntimeLenInfo::empty();
                        len.add_len_field(
                            format!("{id}:size"),
                            ByteLen(str::parse(size_modifier).unwrap()),
                        );
                        len
                    }
                    _ => RuntimeLenInfo::Unbounded,
                },
                size: *size,
            }),
            FieldDesc::Scalar { id, width } => {
                let ftype = ftype_lua_expr(self.annot.size.into());
                Some(FieldDissectorInfo::Scalar {
                    name: String::from(id),
                    abbr: id.into(),
                    ftype,
                    len_bytes: RuntimeLenInfo::fixed(ByteLen::from_bits(*width)),
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

/// Command line arguments for this tool.
#[derive(clap::Parser)]
pub struct Args {
    /// The PDL file to generate the Wireshark dissector from. See
    /// https://github.com/google/pdl/blob/main/doc/reference.md.
    pub pdl_file: PathBuf,
    /// The type in the PDL file to generate dissector for.
    ///
    /// Since a PDL file can contain multiple packet declarations, this
    /// specifies which packet the dissector should be generated for.
    pub target_packets: Vec<String>,
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

    writedoc!(
        writer,
        r#"
        -- Protocol definition for "{decl_name}"
        {decl_name}_protocol = Proto("{decl_name}",  "{decl_name}")
        "#,
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

pub fn run(args: Args, writer: &mut impl std::io::Write) -> anyhow::Result<()> {
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

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use std::{io::BufWriter, path::PathBuf};

    use crate::{fakes::wireshark_lua, run, Args};

    /// Update with `cargo run -- tests/pcap.pdl PcapFile > tests/pcap_golden.lua`
    #[test]
    fn test_pcap() {
        let args = Args {
            pdl_file: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pcap.pdl"),
            target_packets: vec!["PcapFile".into()],
        };
        pretty_assertions::assert_str_eq!(
            include_str!("../tests/pcap_golden.lua"),
            std::str::from_utf8(&run_with_args(args)).unwrap(),
        );
    }

    #[test]
    #[ignore] // Requires unaligned field length
    fn test_bluetooth_hci() -> anyhow::Result<()> {
        let args = Args {
            pdl_file: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bluetooth_hci.pdl"),
            target_packets: vec!["_all_".into()],
        };
        let lua = wireshark_lua()?;
        lua.load(run_with_args(args)).exec()?;
        Ok(())
    }

    #[test]
    fn test_le() -> anyhow::Result<()> {
        let args = Args {
            pdl_file: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_le.pdl"),
            target_packets: vec!["TopLevel".into()],
        };

        let lua = wireshark_lua()?;
        lua.load(run_with_args(args)).exec()?;
        let bytes = hex!("0000");
        lua.load(mlua::chunk! { TopLevel_protocol.dissector(Tvb($bytes), new_pinfo(), Tree()) })
            .exec()?;
        Ok(())
    }

    fn run_with_args(args: Args) -> Vec<u8> {
        let mut writer = BufWriter::new(Vec::new());
        run(args, &mut writer).unwrap();
        writer.into_inner().unwrap()
    }
}
