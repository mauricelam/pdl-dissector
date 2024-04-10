mod comments;
pub mod diagnostics;
#[cfg(test)]
mod fakes;
mod indent_write;
mod len_info;
pub mod pdml;
mod utils;

use ::indent_write::io::IndentWriter;
use codespan_reporting::diagnostic::Diagnostic;
use comments::ToLuaExpr;
use diagnostics::Diagnostics;
use indent_write::IoWriteExt;
use indoc::writedoc;
use len_info::{FType, RuntimeLenInfo};
use log::{debug, info};
use pdl_compiler::{
    analyzer::{self, Scope},
    ast::{
        Annotation, Constraint, Decl, DeclDesc, EndiannessValue, Field, FieldDesc, SourceDatabase,
        Tag, TagOther, TagRange, TagValue,
    },
};
use std::{collections::HashMap, io::Write, path::PathBuf};
use utils::{buffer_value_lua_function, lua_if_then_else};

use crate::{
    comments::{find_comments_on_same_line, unwrap_comment},
    len_info::BitLen,
};

#[derive(Clone, Debug)]
struct FieldContext<'a> {
    num_fixed: usize,
    num_reserved: usize,
    optional_decl: HashMap<String, (String, usize)>,
    scope: &'a Scope<'a, analyzer::ast::Annotation>,
}

impl<'a> FieldContext<'a> {
    pub fn new(scope: &'a Scope<'a, analyzer::ast::Annotation>) -> Self {
        Self {
            num_fixed: 0,
            num_reserved: 0,
            optional_decl: HashMap::default(),
            scope,
        }
    }
}

trait DeclExt {
    fn to_dissector_info(&self, scope: &Scope) -> DeclDissectorInfo;
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
        len: BitLen,
    },
    Checksum {
        name: String,
        len: BitLen,
    },
}

impl DeclDissectorInfo {
    fn to_comments(&self) -> String {
        if log::log_enabled!(log::Level::Debug) {
            format!("{self:?}")
        } else {
            match self {
                DeclDissectorInfo::Sequence {
                    name,
                    fields,
                    children,
                    constraints,
                } => format!(
                    "Sequence: {name} ({} fields, {} children, {} constraints)",
                    fields.len(),
                    children.len(),
                    constraints.len()
                ),
                DeclDissectorInfo::Enum { .. } => format!("{self:?}"),
                DeclDissectorInfo::Checksum { .. } => format!("{self:?}"),
            }
        }
    }

    fn write_proto_fields(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        match self {
            DeclDissectorInfo::Sequence {
                name,
                fields,
                children,
                constraints: _,
            } => {
                writeln!(writer, r#"function {name}_protocol_fields(fields, path)"#)?;
                for field in fields {
                    field.field_declaration(&mut writer.indent())?;
                }
                for child in children {
                    let child_name = child.name();
                    writeln!(
                        writer.indent(),
                        r#"{child_name}_protocol_fields(fields, path .. ".{child_name}")"#
                    )?;
                }
                writeln!(writer, r#"end"#)?;
            }
            DeclDissectorInfo::Enum {
                name,
                values,
                len: _,
            } => {
                writeln!(writer, r#"{name}_enum = ProtoEnum:new()"#)?;
                for tag in values {
                    match tag {
                        Tag::Value(TagValue { id, loc: _, value }) => {
                            writeln!(writer, r#"{name}_enum:define("{id}", {value})"#)?;
                        }
                        Tag::Range(TagRange {
                            id: range_id,
                            loc: _,
                            range,
                            tags,
                        }) => {
                            for TagValue { id, loc: _, value } in tags {
                                writeln!(
                                    writer,
                                    r#"{name}_enum:define("{range_id}: {id}", {value})"#
                                )?;
                            }
                            let range_start = range.start();
                            let range_end = range.end();
                            writeln!(
                                writer,
                                r#"{name}_enum:define("{range_id}", {{{range_start}, {range_end}}})"#
                            )?;
                        }
                        Tag::Other(TagOther { id, loc: _ }) => {
                            writeln!(writer, r#"{name}_enum:define("{id}", nil)"#)?;
                        }
                    }
                }
            }
            DeclDissectorInfo::Checksum { name: _, len: _ } => {}
        }
        Ok(())
    }

    pub fn write_main_dissector(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        match self {
            DeclDissectorInfo::Sequence { name, .. } => {
                writedoc!(
                    writer,
                    r#"
                    {name}_protocol_fields_table = {{}}
                    function {name}_protocol.dissector(buffer, pinfo, tree)
                        pinfo.cols.protocol = "{name}"
                        local subtree = tree:add({name}_protocol, buffer(), "{name}")
                        local i = {name}_dissect(buffer, pinfo, subtree, {name}_protocol_fields_table, "{name}")
                        if buffer(i):len() > 0 then
                            local remaining_bytes = buffer:len() - i
                            if math.floor(remaining_bytes) == remaining_bytes then
                                subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: " .. remaining_bytes .. " undissected bytes remaining")
                            else
                                subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: " .. (remaining_bytes * 8) .. " undissected bits remaining")
                            end
                        end
                    end
                    {name}_protocol_fields({name}_protocol_fields_table, "{name}")
                    for name,field in pairs({name}_protocol_fields_table) do
                        {name}_protocol.fields[name] = field.field
                    end
                    "#,
                )?;
            }
            DeclDissectorInfo::Enum { .. } => unreachable!(),
            DeclDissectorInfo::Checksum { .. } => unreachable!(),
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
                    field_len.add(&field.len());
                }
                field_len
            }
            DeclDissectorInfo::Enum {
                name: _,
                values: _,
                len,
            } => RuntimeLenInfo::fixed(*len),
            DeclDissectorInfo::Checksum { name: _, len } => RuntimeLenInfo::fixed(*len),
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
                    -- {comments}
                    function {name}_dissect(buffer, pinfo, tree, fields, path)
                        local i = 0
                        local field_values = {{}}
                    "#,
                    comments = self.to_comments(),
                )?;
                for field in fields {
                    field.write_dissect_fn(&mut writer.indent())?;
                }
                writedoc!(
                    writer,
                    r#"
                        return i
                    end
                    "#
                )?;
                let constraints_lua = if constraints.is_empty() {
                    String::from("true")
                } else {
                    constraints
                        .iter()
                        .map(|c| c.to_lua_expr())
                        .collect::<Vec<_>>()
                        .join(" and ")
                };
                writedoc!(
                    writer,
                    r#"
                    function {name}_match_constraints(field_values, path)
                        return {constraints_lua}
                    end
                    "#
                )?;
            }
            DeclDissectorInfo::Enum { .. } => {}
            DeclDissectorInfo::Checksum { .. } => {}
        }
        Ok(())
    }

    fn name(&self) -> &str {
        match self {
            DeclDissectorInfo::Sequence { name, .. } => name,
            DeclDissectorInfo::Enum { name, .. } => name,
            DeclDissectorInfo::Checksum { name, .. } => name,
        }
    }
}

impl DeclExt for Decl<analyzer::ast::Annotation> {
    fn to_dissector_info(&self, scope: &Scope) -> DeclDissectorInfo {
        match &self.desc {
            DeclDesc::Enum { id, tags, width } => DeclDissectorInfo::Enum {
                name: id.clone(),
                values: tags.clone(),
                len: BitLen(*width),
            },
            DeclDesc::Checksum { id, width, .. } => DeclDissectorInfo::Checksum {
                name: id.clone(),
                len: BitLen(*width),
            },
            DeclDesc::CustomField { id, .. }
            | DeclDesc::Packet { id, .. }
            | DeclDesc::Struct { id, .. }
            | DeclDesc::Group { id, .. } => {
                let mut bit_offset = BitLen(0);
                DeclDissectorInfo::Sequence {
                    name: id.clone(),
                    fields: {
                        let mut field_dissector_infos = vec![];
                        let mut ctx = FieldContext::new(scope);
                        for field in self.fields() {
                            if let Some(dissector_info) = field.to_dissector_info(
                                &mut ctx,
                                &bit_offset,
                                self,
                                field_dissector_infos.last_mut(),
                            ) {
                                bit_offset.0 =
                                    (bit_offset.0 + dissector_info.len().bit_offset().0) % 8;
                                field_dissector_infos.push(dissector_info);
                            }
                        }
                        field_dissector_infos
                    },
                    children: scope
                        .iter_children(self)
                        .map(|child| child.to_dissector_info(scope))
                        .collect::<Vec<_>>(),
                    constraints: self
                        .constraints()
                        .map(|constraint| constraint.to_dissector_info(scope, self))
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
            } => {
                fn find_ancestor_field<'a>(
                    scope: &'a Scope,
                    decl: &'a Decl<analyzer::ast::Annotation>,
                    predicate: impl Fn(&Field<analyzer::ast::Annotation>) -> bool,
                ) -> Option<&'a Field<analyzer::ast::Annotation>> {
                    match decl.fields().find(|f| predicate(f)) {
                        Some(x) => Some(x),
                        None => scope
                            .get_parent(decl)
                            .and_then(|parent| find_ancestor_field(scope, parent, predicate)),
                    }
                }
                let parent_decl = scope.get_parent(decl).unwrap();
                ConstraintDissectorInfo::EnumMatch {
                    field: id.clone(),
                    enum_type: find_ancestor_field(scope, parent_decl, |f| f.id() == Some(id))
                        .map(|f| match &f.desc {
                            FieldDesc::Typedef { id: _, type_id } => type_id.clone(),
                            _ => unreachable!(),
                        })
                        .unwrap_or_else(|| {
                            panic!("Unable to find field `{id}` in parent {parent_decl:?}")
                        }),
                    enum_value: enum_tag.clone(),
                }
            }
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
                format!(
                    r#"{enum_type}_enum:match("{enum_value}", field_values[path .. ".{field}"])"#
                )
            }
            ConstraintDissectorInfo::ValueMatch { field, value } => {
                format!(r#"field_values[path .. ".{field}"] == {value}"#)
            }
        }
    }
}

trait FieldExt {
    fn to_dissector_info(
        &self,
        ctx: &mut FieldContext,
        bit_offset: &BitLen,
        decl: &Decl<pdl_compiler::analyzer::ast::Annotation>,
        last_field: Option<&mut FieldDissectorInfo>,
    ) -> Option<FieldDissectorInfo>;
}

#[derive(Debug, Clone)]
pub struct CommonFieldDissectorInfo {
    /// Actual name of the field (the string that appears in the tree).
    display_name: String,
    /// Filter name of the field (the string that is used in filters).
    abbr: String,
    bit_offset: BitLen,
    endian: EndiannessValue,
    comments: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArrayFieldDissectorInfo {
    /// Number of items in the array, or `None` if the array is unbounded
    count: Option<usize>,
    size_modifier: Option<String>,
    pad_to_size: Option<usize>,
    has_size_field: bool,
    has_count_field: bool,
}

#[derive(Debug, Clone)]
pub enum FieldDissectorInfo {
    Scalar {
        common: CommonFieldDissectorInfo,
        ftype: FType,
        /// The length this field takes before repetition.
        len: RuntimeLenInfo,
        /// A lua-expression that yields a boolean value. If the boolean result
        /// is false, a warning will be shown in the dissected info. `value` is
        /// a variable that can be used to get the value of this field.
        validate_expr: Option<String>,
        /// (optional field name, match value)
        optional_field: Option<(String, usize)>,
    },
    Payload {
        common: CommonFieldDissectorInfo,
        ftype: FType,
        /// The length this field takes before repetition.
        len: RuntimeLenInfo,
        children: Vec<String>,
    },
    Typedef {
        common: CommonFieldDissectorInfo,
        decl: Box<DeclDissectorInfo>,
        /// (optional field name, match value)
        optional_field: Option<(String, usize)>,
    },
    TypedefArray {
        common: CommonFieldDissectorInfo,
        decl: Box<DeclDissectorInfo>,
        array_info: ArrayFieldDissectorInfo,
    },
    ScalarArray {
        common: CommonFieldDissectorInfo,
        ftype: FType,
        item_len: BitLen,
        array_info: ArrayFieldDissectorInfo,
    },
}

impl FieldDissectorInfo {
    pub fn to_comments(&self) -> String {
        if log::log_enabled!(log::Level::Debug) {
            format!("{self:?}")
        } else {
            match self {
                FieldDissectorInfo::Scalar {
                    common: CommonFieldDissectorInfo { display_name, .. },
                    ..
                } => format!("Scalar: {display_name}"),
                FieldDissectorInfo::Payload {
                    common: CommonFieldDissectorInfo { display_name, .. },
                    ..
                } => format!("Payload: {display_name}"),
                FieldDissectorInfo::Typedef {
                    common: CommonFieldDissectorInfo { display_name, .. },
                    ..
                } => format!("Typedef: {display_name}"),
                FieldDissectorInfo::TypedefArray {
                    common: CommonFieldDissectorInfo { display_name, .. },
                    ..
                } => format!("TypedefArray: {display_name}"),
                FieldDissectorInfo::ScalarArray {
                    common: CommonFieldDissectorInfo { display_name, .. },
                    ..
                } => format!("ScalarArray: {display_name}"),
            }
        }
    }

    pub fn is_unaligned(&self) -> bool {
        match self {
            FieldDissectorInfo::Scalar { common, ftype, .. }
            | FieldDissectorInfo::Payload { common, ftype, .. } => {
                common.bit_offset.0 % 8 != 0
                    || ftype.0.map(|len| len.0 % 8 != 0).unwrap_or_default()
            }
            _ => false,
        }
    }

    /// Returns a tuple (field_name, lua_expression, field_length), or `None` if no ProtoFields
    /// need to be defined.
    pub fn field_declaration(
        &self,
        writer: &mut impl std::io::Write,
    ) -> Result<(), std::io::Error> {
        match self {
            FieldDissectorInfo::Scalar { common, ftype, .. }
            | FieldDissectorInfo::ScalarArray { common, ftype, .. }
            | FieldDissectorInfo::Payload { common, ftype, .. } => {
                let CommonFieldDissectorInfo {
                    display_name,
                    abbr,
                    bit_offset,
                    endian,
                    comments,
                } = common;
                let bitlen = ftype
                    .0
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| String::from("nil"));
                if self.is_unaligned() {
                    writedoc!(
                        writer,
                        r#"
                        fields[path .. ".{abbr}"] = UnalignedProtoField:new({{
                            name = "{display_name}",
                            abbr = path .. ".{abbr}",
                            ftype = {ftype},
                            bitoffset = {bit_offset},
                            bitlen = {bitlen},
                            is_little_endian = {is_le},
                            description = {description},
                        }})
                        "#,
                        ftype = ftype.to_lua_expr(),
                        is_le = *endian == EndiannessValue::LittleEndian,
                        description = comments.as_deref().to_lua_expr(),
                    )?;
                } else {
                    writedoc!(
                        writer,
                        r#"
                        fields[path .. ".{abbr}"] = AlignedProtoField:new({{
                            name = "{display_name}",
                            abbr = path .. ".{abbr}",
                            ftype = {ftype},
                            bitlen = {bitlen},
                            is_little_endian = {is_le},
                            description = {description},
                        }})
                        "#,
                        ftype = ftype.to_lua_expr(),
                        is_le = *endian == EndiannessValue::LittleEndian,
                        description = comments.as_deref().to_lua_expr(),
                    )?;
                }
            }
            FieldDissectorInfo::Typedef { common, decl, .. }
            | FieldDissectorInfo::TypedefArray { common, decl, .. } => {
                let CommonFieldDissectorInfo {
                    display_name,
                    abbr,
                    bit_offset,
                    endian,
                    comments,
                } = common;
                match decl.as_ref() {
                    DeclDissectorInfo::Sequence { fields, .. } => {
                        for field in fields {
                            field.field_declaration(writer)?;
                        }
                    }
                    DeclDissectorInfo::Enum {
                        name: type_name,
                        values: _,
                        len,
                    } => {
                        let ftype = FType(Some(*len));
                        if len.0 % 8 == 0 {
                            writedoc!(
                                writer,
                                r#"
                            fields[path .. ".{abbr}"] = AlignedProtoField:new({{
                                name = "{display_name}",
                                abbr = "{abbr}",
                                ftype = {ftype},
                                valuestring = {type_name}_enum.matchers,
                                base = base.RANGE_STRING,
                                is_little_endian = {is_le},
                                description = {description},
                            }})
                            "#,
                                ftype = ftype.to_lua_expr(),
                                is_le = *endian == EndiannessValue::LittleEndian,
                                description = comments.as_deref().to_lua_expr(),
                            )?;
                        } else {
                            writedoc!(
                                writer,
                                r#"
                                fields[path .. ".{abbr}"] = UnalignedProtoField:new({{
                                    name = "{display_name}",
                                    abbr = "{abbr}",
                                    ftype = {ftype},
                                    valuestring = {type_name}_enum.matchers,
                                    bitoffset = {bit_offset},
                                    bitlen = {len},
                                    is_little_endian = {is_le},
                                }})
                                "#,
                                ftype = ftype.to_lua_expr(),
                                is_le = *endian == EndiannessValue::LittleEndian,
                            )?;
                        }
                    }
                    DeclDissectorInfo::Checksum {
                        name: _type_name,
                        len,
                    } => {
                        let ftype = FType(Some(*len));
                        writedoc!(
                            writer,
                            r#"
                            fields[path .. ".{abbr}"] = AlignedProtoField:new({{
                                name = "{display_name}",
                                abbr = "{abbr}",
                                ftype = {ftype},
                                base = base.HEX,
                                is_little_endian = {is_le},
                            }})
                            "#,
                            ftype = ftype.to_lua_expr(),
                            is_le = *endian == EndiannessValue::LittleEndian,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn len(&self) -> RuntimeLenInfo {
        match self {
            Self::Scalar { len, .. } => len.clone(),
            Self::Payload { len, .. } => len.clone(),
            Self::Typedef { decl, .. } => decl.decl_len(),
            Self::TypedefArray { decl, .. } => decl.decl_len(),
            Self::ScalarArray { item_len, .. } => RuntimeLenInfo::Bounded {
                referenced_fields: vec![],
                constant_factor: *item_len,
            },
        }
    }

    pub fn write_dissect_fn(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        match self {
            FieldDissectorInfo::Scalar {
                common,
                validate_expr,
                optional_field,
                ..
            } => match optional_field {
                Some((optional_field, optional_match_value)) => {
                    writedoc!(
                        writer,
                        r#"
                        if field_values[path .. ".{optional_field}"] == {optional_match_value} then
                        "#
                    )?;
                    self.write_scalar_dissect(
                        &mut writer.indent(),
                        &common.abbr,
                        &[],
                        validate_expr.clone(),
                    )?;
                    writeln!(writer, "end")?;
                }
                None => {
                    self.write_scalar_dissect(writer, &common.abbr, &[], validate_expr.clone())?
                }
            },
            FieldDissectorInfo::Payload {
                common, children, ..
            } => {
                self.write_scalar_dissect(writer, &common.abbr, children, None)?;
            }
            FieldDissectorInfo::Typedef {
                common,
                decl,
                optional_field,
            } => match optional_field {
                Some((optional_field, optional_match_value)) => {
                    writedoc!(
                        writer,
                        r#"
                        if field_values[path .. ".{optional_field}"] == {optional_match_value} then
                        "#
                    )?;
                    self.write_typedef_dissect(
                        &mut writer.indent(),
                        decl,
                        &common.display_name,
                        &common.abbr,
                        common.endian,
                    )?;
                    writeln!(writer, "end")?;
                }
                None => self.write_typedef_dissect(
                    writer,
                    decl,
                    &common.display_name,
                    &common.abbr,
                    common.endian,
                )?,
            },
            FieldDissectorInfo::TypedefArray {
                common,
                decl,
                array_info,
            } => {
                let CommonFieldDissectorInfo {
                    display_name, abbr, ..
                } = common;
                self.write_array_dissect(writer, common, array_info, |w| {
                    self.write_typedef_dissect(w, decl, display_name, abbr, common.endian)
                })?;
                if let Some(octet_size) = array_info.pad_to_size {
                    writedoc!(
                        writer,
                        r#"
                        if i - initial_i < {octet_size} then
                            tree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected a minimum of {octet_size} octets in field `{display_name}`")
                        end
                        "#
                    )?;
                }
            }
            FieldDissectorInfo::ScalarArray {
                common, array_info, ..
            } => {
                self.write_array_dissect(writer, common, array_info, |w| {
                    self.write_scalar_dissect(w, &common.abbr, &[], None)
                })?;
            }
        }
        Ok(())
    }

    pub fn write_scalar_dissect(
        &self,
        writer: &mut impl std::io::Write,
        abbr: &str,
        children: &[String],
        validate_expr: Option<String>,
    ) -> std::io::Result<()> {
        let len_expr = self.len().to_lua_expr();
        writedoc!(
            writer,
            r#"
            -- {comments}
            local field_len = enforce_len_limit({len_expr}, buffer(i):len(), tree)
            "#,
            comments = self.to_comments()
        )?;
        lua_if_then_else(
            &mut *writer,
            children.iter().map(|child_name| {
                (
                    format!("{child_name}_match_constraints(field_values, path)"),
                    move |w: &mut dyn std::io::Write| writedoc!(
                        w,
                        r#"
                        local subtree = tree:add("{child_name}")
                        local dissected_len = {child_name}_dissect(buffer(i, field_len), pinfo, subtree, fields, path .. ".{child_name}")
                        i = i + dissected_len
                        "#,
                    )
                )
            }),
            Some(|w: &mut dyn std::io::Write| {
                writedoc!(
                    w,
                    r#"
                    subtree, field_values[path .. ".{abbr}"], bitlen = fields[path .. ".{abbr}"]:dissect(tree, buffer(i), field_len)
                    i = i + bitlen / 8
                    "#,
                )?;
                if let Some(validate) = validate_expr.as_ref() {
                    writedoc!(
                        w,
                        r#"
                        local value = field_values[path .. ".{abbr}"]
                        if not ({validate}) then
                            subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected `{validate_escaped}` where value=" .. tostring(value))
                        end
                        "#,
                        validate_escaped = validate.replace('\\', "\\\\").replace('"', "\\\"")
                    )?;
                }
                Ok(())
            }))?;
        Ok(())
    }

    pub fn write_typedef_dissect(
        &self,
        writer: &mut impl std::io::Write,
        decl: &DeclDissectorInfo,
        name: &str,
        abbr: &str,
        endian: EndiannessValue,
    ) -> std::io::Result<()> {
        match decl {
            DeclDissectorInfo::Sequence {
                name: type_name, ..
            } => {
                let len_expr = decl.decl_len().to_lua_expr();
                writedoc!(
                    writer,
                    r#"
                    -- {comments}
                    local field_len = enforce_len_limit({len_expr}, buffer(i):len(), tree)
                    local subtree = tree:add(buffer(i, field_len), "{name}")
                    local dissected_len = {type_name}_dissect(buffer(i, field_len), pinfo, subtree, fields, path)
                    subtree:set_len(dissected_len)
                    i = i + dissected_len
                    "#,
                    comments = self.to_comments(),
                )?;
            }
            DeclDissectorInfo::Enum {
                name: type_name, ..
            } => {
                let len_expr = self.len().to_lua_expr();
                writedoc!(
                    writer,
                    r#"
                    -- {comments}
                    local field_len = enforce_len_limit(math.ceil({len_expr}), buffer(i):len(), tree)
                    subtree, field_values[path .. ".{name}"], bitlen = fields[path .. ".{abbr}"]:dissect(tree, buffer(i), field_len)
                    if {type_name}_enum.by_value[field_values[path .. ".{name}"]] == nil then
                        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown enum value: " .. field_values[path .. ".{name}"])
                    end
                    i = i + bitlen / 8
                    "#,
                    comments = self.to_comments(),
                )?;
            }
            DeclDissectorInfo::Checksum {
                name: _type_name,
                len,
            } => {
                let add_fn = match endian {
                    EndiannessValue::LittleEndian => "add_le",
                    EndiannessValue::BigEndian => "add",
                };
                let len_expr = self.len().to_lua_expr();
                let buffer_value_function =
                    buffer_value_lua_function(endian, &RuntimeLenInfo::fixed(*len));
                writedoc!(
                    writer,
                    r#"
                    -- {comments}
                    local field_len = enforce_len_limit({len_expr}, buffer(i):len(), tree)
                    field_values[path .. ".{name}"] = buffer(i, field_len):{buffer_value_function}
                    if field_len ~= 0 then
                        tree:{add_fn}(fields[path .. ".{abbr}"].field, buffer(i, field_len))
                        i = i + field_len
                    end
                    "#,
                    comments = self.to_comments(),
                )?;
            }
        }
        Ok(())
    }

    fn write_array_dissect<W: std::io::Write>(
        &self,
        writer: &mut W,
        common_info: &CommonFieldDissectorInfo,
        array_info: &ArrayFieldDissectorInfo,
        write_item_dissect: impl Fn(&mut IndentWriter<&mut W>) -> Result<(), std::io::Error>,
    ) -> Result<(), std::io::Error> {
        let CommonFieldDissectorInfo {
            display_name, abbr, ..
        } = common_info;
        let ArrayFieldDissectorInfo {
            count,
            size_modifier,
            ..
        } = array_info;
        if size_modifier.is_some() {
            assert!(
                array_info.has_size_field,
                "Size modifier is defined but a size field is not found for `{abbr}`",
                abbr = common_info.abbr,
            );
        }
        if count.is_some() {
            assert!(
                !array_info.has_count_field,
                "Count field is defined for `{abbr}`, but it has fixed item count",
                abbr = common_info.abbr,
            );
        }
        assert!(
            !((count.is_some() || array_info.has_count_field) && array_info.has_size_field),
            "Size and count cannot be specified for the same array `{abbr}`"
        );
        writedoc!(
            writer,
            r#"
            -- {comments}
            local initial_i = i
            "#,
            comments = self.to_comments(),
        )?;
        if array_info.has_count_field {
            writedoc!(
                writer,
                r#"
                for j=1,field_values[path .. ".{abbr}_count"] do
                    -- Warn if there isn't enough elements to fit the expected count
                    if i >= buffer:len() and j <= {count} then
                        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected " .. {count} .. " `{display_name}` items but only found " .. (j - 1))
                        break
                    end
                "#,
                count = format!(r#"field_values[path .. ".{abbr}_count"]"#),
            )?;
        } else if let Some(count) = count {
            writedoc!(
                writer,
                r#"
                for j=1,{count} do
                    -- Warn if there isn't enough elements to fit the expected count
                    if i >= buffer:len() and j <= {count} then
                        tree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Expected {count} `{display_name}` items but only found " .. (j - 1))
                        break
                    end
                "#
            )?;
        } else if array_info.has_size_field {
            // Check that the array doesn't exceed the size() field
            writedoc!(
                writer,
                r#"
                if initial_i + field_values[path .. ".{abbr}_size"]{size_modifier} > buffer:len() then
                    tree:add_expert_info(PI_MALFORMED, PI_WARN, "Error: Size({display_name}) is greater than the number of remaining bytes")
                end
                while i < buffer:len() and i - initial_i < field_values[path .. ".{abbr}_size"]{size_modifier} do
                "#,
                size_modifier = size_modifier.as_deref().unwrap_or_default(),
            )?;
        } else {
            writedoc!(writer, r#"while i < buffer:len() do"#)?;
        }
        write_item_dissect(&mut writer.indent())?;
        writeln!(writer, "end")?;
        Ok(())
    }
}

impl FieldExt for Field<analyzer::ast::Annotation> {
    fn to_dissector_info(
        &self,
        ctx: &mut FieldContext,
        bit_offset: &BitLen,
        decl: &Decl<pdl_compiler::analyzer::ast::Annotation>,
        last_field: Option<&mut FieldDissectorInfo>,
    ) -> Option<FieldDissectorInfo> {
        debug!(
            "Write field: {:?}\nannot={:?}\ndecl={:?}",
            self, self.annot, decl
        );
        match &self.desc {
            FieldDesc::Checksum { field_id: _ } => {
                // This is the `_checksum_start_` field.
                // Actual checksum field is a TypeDef.
                None
            }
            FieldDesc::Padding { size: octet_size } => {
                match last_field.unwrap() {
                    FieldDissectorInfo::TypedefArray {
                        common, array_info, ..
                    }
                    | FieldDissectorInfo::ScalarArray {
                        common, array_info, ..
                    } => {
                        common.display_name = format!(
                            "{display_name} (Padded)",
                            display_name = common.display_name
                        );
                        array_info.pad_to_size = Some(*octet_size);
                    }
                    _ => unreachable!(),
                }
                None
            }
            FieldDesc::Size { field_id, width } => {
                let ftype = FType::from(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    common: CommonFieldDissectorInfo {
                        display_name: format!(
                            "Size({field_name})",
                            field_name = match field_id.as_str() {
                                "_payload_" => "Payload",
                                _ => field_id,
                            }
                        ),
                        abbr: format!("{field_id}_size"),
                        bit_offset: *bit_offset,
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    ftype,
                    len: RuntimeLenInfo::fixed(BitLen(*width)),
                    validate_expr: None,
                    optional_field: None,
                })
            }
            FieldDesc::Count { field_id, width } => {
                let ftype = FType::from(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    common: CommonFieldDissectorInfo {
                        display_name: format!(
                            "Count({field_id})",
                            field_id = match field_id.as_str() {
                                "_payload_" => "Payload",
                                _ => field_id,
                            }
                        ),
                        abbr: format!("{field_id}_count"),
                        bit_offset: *bit_offset,
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    ftype,
                    len: RuntimeLenInfo::fixed(BitLen(width * 8)),
                    validate_expr: None,
                    optional_field: None,
                })
            }
            FieldDesc::ElementSize { .. } => {
                // This `_elementsize_` field is undocumented (in
                // https://github.com/google/pdl/blob/main/doc/reference.md) and untested in the PDL
                // repo. Ignore it for now.
                unimplemented!()
            }
            FieldDesc::Body => {
                let children = ctx
                    .scope
                    .iter_children(decl)
                    .filter_map(|child_decl| child_decl.id().map(|c| c.to_string()))
                    .collect::<Vec<_>>();
                let ftype = FType::from(self.annot.size);
                let mut field_len = RuntimeLenInfo::empty();
                field_len.add_len_field("_body__size".into(), BitLen(0));
                Some(FieldDissectorInfo::Payload {
                    common: CommonFieldDissectorInfo {
                        display_name: String::from("Body"),
                        abbr: "_body_".into(),
                        bit_offset: *bit_offset,
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    ftype,
                    len: field_len,
                    children,
                })
            }
            FieldDesc::Payload { size_modifier } => {
                let mut field_len = RuntimeLenInfo::empty();
                field_len.add_len_field(
                    "_payload__size".into(),
                    size_modifier
                        .as_ref()
                        .map(|s| BitLen(s.parse::<usize>().unwrap() * 8))
                        .unwrap_or_default(),
                );
                Some(FieldDissectorInfo::Payload {
                    common: CommonFieldDissectorInfo {
                        display_name: String::from("Payload"),
                        abbr: "_payload_".into(),
                        bit_offset: *bit_offset,
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    ftype: FType::from(self.annot.size),
                    len: field_len,
                    children: vec![],
                })
            }
            FieldDesc::FixedScalar { width, value } => {
                ctx.num_fixed += 1;
                Some(FieldDissectorInfo::Scalar {
                    common: CommonFieldDissectorInfo {
                        display_name: "Fixed value".into(),
                        abbr: format!("_fixed_{}", ctx.num_fixed - 1),
                        bit_offset: *bit_offset,
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    ftype: FType::from(self.annot.size),
                    len: RuntimeLenInfo::fixed(BitLen(*width)),
                    validate_expr: Some(format!("value == {value}")),
                    optional_field: None,
                })
            }
            FieldDesc::FixedEnum { enum_id, tag_id } => {
                ctx.num_fixed += 1;
                let referenced_enum = ctx.scope.typedef[enum_id].to_dissector_info(ctx.scope);
                let ftype = FType::from(self.annot.size);
                Some(FieldDissectorInfo::Scalar {
                    common: CommonFieldDissectorInfo {
                        display_name: format!("Fixed value: {tag_id}"),
                        abbr: format!("_fixed_{}", ctx.num_fixed - 1),
                        bit_offset: *bit_offset,
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    ftype,
                    len: referenced_enum.decl_len(),
                    validate_expr: Some(format!(r#"{enum_id}_enum:match("{tag_id}", value)"#)),
                    optional_field: None,
                })
            }
            FieldDesc::Reserved { width } => {
                ctx.num_reserved += 1;
                Some(FieldDissectorInfo::Scalar {
                    common: CommonFieldDissectorInfo {
                        display_name: String::from("Reserved"),
                        abbr: format!("_reserved_{}", ctx.num_reserved - 1),
                        bit_offset: *bit_offset,
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    ftype: FType(Some(BitLen(*width))),
                    len: RuntimeLenInfo::fixed(BitLen(*width)),
                    validate_expr: None,
                    optional_field: None,
                })
            }
            FieldDesc::Array {
                id,
                width,
                type_id,
                size_modifier,
                size,
            } => match (width, type_id) {
                (None, Some(type_id)) => Some(FieldDissectorInfo::TypedefArray {
                    common: CommonFieldDissectorInfo {
                        display_name: id.clone(),
                        abbr: id.clone(),
                        bit_offset: *bit_offset,
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    decl: Box::new(
                        ctx.scope
                            .typedef
                            .get(type_id)
                            .copied()
                            .expect("Unresolved typedef")
                            .to_dissector_info(ctx.scope),
                    ),
                    array_info: ArrayFieldDissectorInfo {
                        size_modifier: size_modifier.clone(),
                        count: *size,
                        pad_to_size: None,
                        has_size_field: has_size_field(decl, id),
                        has_count_field: has_count_field(decl, id),
                    },
                }),
                (Some(width), None) => Some(FieldDissectorInfo::ScalarArray {
                    common: CommonFieldDissectorInfo {
                        display_name: id.clone(),
                        abbr: id.clone(),
                        bit_offset: BitLen::default(),
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    array_info: ArrayFieldDissectorInfo {
                        count: *size,
                        size_modifier: size_modifier.clone(),
                        pad_to_size: None,
                        has_size_field: has_size_field(decl, id),
                        has_count_field: has_count_field(decl, id),
                    },
                    ftype: FType(Some(BitLen(*width))),
                    item_len: BitLen(*width),
                }),
                _ => unreachable!(),
            },
            FieldDesc::Scalar { id, width } => Some(FieldDissectorInfo::Scalar {
                common: CommonFieldDissectorInfo {
                    display_name: String::from(id),
                    abbr: id.into(),
                    bit_offset: *bit_offset,
                    endian: ctx.scope.file.endianness.value,
                    comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                        .map(|comment| unwrap_comment(&comment.text).to_string()),
                },
                ftype: FType(Some(BitLen(*width))),
                len: RuntimeLenInfo::fixed(BitLen(*width)),
                validate_expr: None,
                optional_field: ctx.optional_decl.get(id).cloned(),
            }),
            FieldDesc::Flag {
                id,
                optional_field_id,
                set_value,
            } => {
                ctx.optional_decl
                    .insert(optional_field_id.clone(), (id.clone(), *set_value));
                Some(FieldDissectorInfo::Scalar {
                    common: CommonFieldDissectorInfo {
                        display_name: String::from(id),
                        abbr: id.into(),
                        bit_offset: *bit_offset,
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    ftype: FType::from(self.annot.size),
                    len: RuntimeLenInfo::fixed(BitLen(1)),
                    validate_expr: None,
                    optional_field: None,
                })
            }
            FieldDesc::Typedef { id, type_id } => {
                let dissector_info = ctx
                    .scope
                    .typedef
                    .get(type_id)
                    .copied()
                    .expect("Unresolved typedef")
                    .to_dissector_info(ctx.scope);
                Some(FieldDissectorInfo::Typedef {
                    common: CommonFieldDissectorInfo {
                        display_name: id.into(),
                        abbr: id.into(),
                        bit_offset: *bit_offset,
                        endian: ctx.scope.file.endianness.value,
                        comments: find_comments_on_same_line(ctx.scope.file, &self.loc)
                            .map(|comment| unwrap_comment(&comment.text).to_string()),
                    },
                    decl: Box::new(dissector_info),
                    optional_field: ctx.optional_decl.get(id).cloned(),
                })
            }
            FieldDesc::Group { .. } => unreachable!(), // Groups are inlined by the time they reach here
        }
    }
}

fn has_size_field(decl: &Decl<analyzer::ast::Annotation>, id: &str) -> bool {
    decl.fields().any(|field| match &field.desc {
        FieldDesc::Size { field_id, .. } => field_id == id,
        _ => false,
    })
}

fn has_count_field(decl: &Decl<analyzer::ast::Annotation>, id: &str) -> bool {
    decl.fields().any(|field| match &field.desc {
        FieldDesc::Count { field_id, .. } => field_id == id,
        _ => false,
    })
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
) -> std::io::Result<()> {
    let target_dissector_info = decl.to_dissector_info(scope);

    writedoc!(
        writer,
        r#"
        -- Protocol definition for "{decl_name}"
        {decl_name}_protocol = Proto("{decl_name}",  "{decl_name}")
        "#,
    )?;

    target_dissector_info.write_main_dissector(writer)?;
    Ok(())
}

pub fn run(
    args: Args,
    sources: &mut SourceDatabase,
    writer: &mut impl std::io::Write,
) -> Result<(), Diagnostics> {
    let _ = env_logger::try_init();

    let file = pdl_compiler::parser::parse_file(
        sources,
        args.pdl_file
            .to_str()
            .expect("pdl_file path should be a valid string"),
    )?;
    let analyzed_file = analyzer::analyze(&file)?;
    let scope = Scope::new(&analyzed_file)?;
    if args.target_packets.is_empty() {
        Err(Diagnostic::error().with_message("Target packet must be specified"))?
    }

    write!(writer, "{}", include_str!("utils.lua"))?;
    for target_packet in args.target_packets {
        for decl in analyzed_file.declarations.iter() {
            let decl_dissector_info = decl.to_dissector_info(&scope);
            decl_dissector_info.write_proto_fields(writer)?;
            decl_dissector_info.write_dissect_fn(writer)?;
        }
        if target_packet == "_all_" {
            for decl in analyzed_file.declarations.iter() {
                if matches!(decl.desc, DeclDesc::Packet { .. }) {
                    generate_for_decl(decl.id().unwrap(), decl, &scope, writer)?;
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
                Err(Diagnostic::error()
                    .with_message(format!("Unable to find declaration {target_packet:?}")))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{io::BufWriter, path::PathBuf};

    use pdl_compiler::ast::SourceDatabase;

    use crate::{fakes::wireshark_lua, run, Args};

    #[test]
    fn test_bluetooth_hci() -> anyhow::Result<()> {
        let args = Args {
            pdl_file: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/compilation_test/bluetooth_hci.pdl"),
            target_packets: vec!["_all_".into()],
        };
        let lua = wireshark_lua()?;
        lua.load(run_with_args(args)).exec()?;
        Ok(())
    }

    #[test]
    fn test_le_test_file() -> anyhow::Result<()> {
        // Copied from pdl-compiler/tests/canonical/le_test_file.pdl
        let args = Args {
            pdl_file: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/compilation_test/le_test_file.pdl"),
            target_packets: vec!["_all_".into()],
        };
        let lua = wireshark_lua()?;
        lua.load(run_with_args(args)).exec()?;
        Ok(())
    }

    #[test]
    fn test_format_bitstring() -> anyhow::Result<()> {
        let lua = wireshark_lua()?;
        lua.load(include_str!("utils.lua")).exec()?;
        lua.load(mlua::chunk! {
            function assert_eq(expected, actual)
                assert(expected == actual, "Expected \"" .. tostring(expected) .. "\" but was \"" .. tostring(actual) .. "\"")
            end
            assert_eq("0010 0101 01", format_bitstring("0010010101"));
            assert_eq("0010 0101", format_bitstring("00100101"));
            assert_eq("...0 0100 101. .... ..", format_bitstring("...00100101......."));
        })
        .exec()?;
        Ok(())
    }

    fn run_with_args(args: Args) -> Vec<u8> {
        let mut writer = BufWriter::new(Vec::new());
        run(args, &mut SourceDatabase::new(), &mut writer).unwrap();
        writer.into_inner().unwrap()
    }
}
