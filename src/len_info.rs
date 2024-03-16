use std::fmt::{Display, Write};

use pdl_compiler::analyzer::ast::Size;

/// Representation of length info that is resolvable at runtime, in bytes.
#[derive(Debug, Clone)]
pub enum RuntimeLenInfo {
    /// The field length is bounded. The resulting length is given by
    /// `SUM(valueof(referenced_fields)) + constant_factor`.
    Bounded {
        referenced_fields: Vec<String>,
        constant_factor: BitLen,
    },
    /// The field length is unbounded, e.g. if this is an array without a fixed
    /// size.
    Unbounded,
}

impl RuntimeLenInfo {
    pub fn empty() -> Self {
        Self::fixed(BitLen(0))
    }

    pub fn fixed(size: BitLen) -> Self {
        Self::Bounded {
            referenced_fields: Vec::new(),
            constant_factor: size,
        }
    }

    pub fn bit_offset(&self) -> BitLen {
        match self {
            RuntimeLenInfo::Bounded {
                referenced_fields: _,
                constant_factor,
            } => *constant_factor,
            // TODO: Can unbounded array be unaligned?
            RuntimeLenInfo::Unbounded => BitLen(0),
        }
    }

    pub fn add_len_field(&mut self, field: String, modifier: BitLen) {
        match self {
            RuntimeLenInfo::Bounded {
                referenced_fields,
                constant_factor,
            } => {
                constant_factor.0 += modifier.0;
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
                constant_factor: BitLen(constant_factor.0 + other_constant_factor.0),
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
                let mut output_code = format!("sum_or_nil({constant_factor} / 8");
                for field in referenced_fields {
                    write!(output_code, r#", field_values[path .. ".{field}"]"#).unwrap();
                }
                write!(output_code, ")").unwrap();
                output_code
            }
            RuntimeLenInfo::Unbounded => "nil".into(),
        }
    }
}

impl From<Size> for RuntimeLenInfo {
    fn from(value: Size) -> Self {
        match value {
            Size::Static(v) => RuntimeLenInfo::Bounded {
                referenced_fields: Vec::new(),
                constant_factor: BitLen(v),
            },
            Size::Dynamic => RuntimeLenInfo::Unbounded,
            Size::Unknown => RuntimeLenInfo::Unbounded,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BitLen(pub usize);

impl Display for BitLen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone)]
pub struct FType(pub Option<BitLen>);

impl FType {
    pub fn to_lua_expr(&self) -> &'static str {
        match self.0 {
            Some(BitLen(1..=8)) => "ftypes.UINT8",
            Some(BitLen(9..=16)) => "ftypes.UINT16",
            Some(BitLen(17..=24)) => "ftypes.UINT24",
            Some(BitLen(25..=32)) => "ftypes.UINT32",
            Some(BitLen(33..=64)) => "ftypes.UINT64",
            _ => "ftypes.BYTES",
        }
    }

    pub fn to_type_len(&self) -> Option<usize> {
        match self.0 {
            Some(BitLen(1..=8)) => Some(8),
            Some(BitLen(9..=16)) => Some(16),
            Some(BitLen(17..=24)) => Some(24),
            Some(BitLen(25..=32)) => Some(32),
            Some(BitLen(33..=64)) => Some(64),
            _ => None,
        }
    }
}

impl From<Size> for FType {
    fn from(value: Size) -> Self {
        match value {
            Size::Static(v) => FType(Some(BitLen(v))),
            Size::Dynamic => FType(None),
            Size::Unknown => FType(None),
        }
    }
}
