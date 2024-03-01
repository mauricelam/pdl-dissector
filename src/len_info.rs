use std::fmt::{Display, Write};

use pdl_compiler::analyzer::ast::Size;

/// Representation of length info that is resolvable at runtime, in bytes.
#[derive(Debug, Clone)]
pub enum RuntimeLenInfo {
    /// The field length is bounded. The resulting length is given by
    /// `SUM(valueof(referenced_fields)) + constant_factor`.
    Bounded {
        referenced_fields: Vec<String>,
        constant_factor: ByteLen,
    },
    /// The field length is unbounded, e.g. if this is an array without a fixed
    /// size.
    Unbounded,
}

impl RuntimeLenInfo {
    pub fn empty() -> Self {
        Self::fixed(ByteLen(0))
    }

    pub fn fixed(size: ByteLen) -> Self {
        Self::Bounded {
            referenced_fields: Vec::new(),
            constant_factor: size,
        }
    }

    pub fn add_len_field(&mut self, field: String, modifier: ByteLen) {
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
                constant_factor: ByteLen(constant_factor.0 + other_constant_factor.0),
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

impl From<Size> for RuntimeLenInfo {
    fn from(value: Size) -> Self {
        match value {
            Size::Static(v) => RuntimeLenInfo::Bounded {
                referenced_fields: Vec::new(),
                constant_factor: ByteLen::from_bits(v),
            },
            Size::Dynamic => RuntimeLenInfo::Unbounded,
            Size::Unknown => RuntimeLenInfo::Unbounded,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ByteLen(pub usize);

impl ByteLen {
    pub fn from_bits(bits: usize) -> Self {
        assert!(bits % 8 == 0, "Unaligned sizes are not supported");
        ByteLen(bits / 8)
    }
}

impl Display for ByteLen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
