//! Pre-effect bounds and fail-closed validation for canonical JSON values.
//!
//! A [`BoundedJsonDescriptor`] is derived entirely from declared maxima. Its
//! canonical-byte ceiling is computed before any value is observed. Validating
//! a value is a separate operation and can never enlarge that ceiling.

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use thiserror::Error;

use crate::{CanonicalizationError, canonical_json_bytes};

/// Largest nesting depth accepted by a bounded-JSON descriptor.
///
/// The limit bounds descriptor construction itself when descriptors are read
/// from untrusted contract material. A root scalar or empty container has
/// depth one.
pub const MAX_BOUNDED_JSON_DEPTH: u16 = 256;

/// Largest canonical decimal width of an integer in the I-JSON exact range.
///
/// `-9007199254740991` is the widest integer accepted by NQ's JCS
/// canonicalizer. Wider integers must be represented by a typed decimal
/// string under a separate schema.
pub const MAX_I_JSON_INTEGER_DECIMAL_WIDTH: u8 = 17;

const MAX_EXACT_I_JSON_INTEGER: i64 = 9_007_199_254_740_991;

/// An immutable, mechanically closed bound for one canonical JSON value.
///
/// The canonical-byte ceiling is not caller selected. [`Self::new`] derives
/// it using checked arithmetic from the remaining structural maxima. This
/// makes the descriptor suitable for pre-effect capacity calculation: a
/// later observed value can fit or refuse, but cannot choose a larger bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundedJsonDescriptor {
    #[serde(rename = "maximum_canonical_bytes")]
    canonical_bytes: u64,
    #[serde(rename = "maximum_depth")]
    depth: u16,
    #[serde(rename = "maximum_properties_per_object")]
    properties_per_object: u32,
    #[serde(rename = "maximum_array_items")]
    array_items: u32,
    #[serde(rename = "maximum_key_utf8_bytes")]
    key_utf8_bytes: u64,
    #[serde(rename = "maximum_string_utf8_bytes")]
    string_utf8_bytes: u64,
    #[serde(rename = "maximum_integer_decimal_width")]
    integer_decimal_width: u8,
}

impl BoundedJsonDescriptor {
    /// Constructs a descriptor and derives its canonical-byte ceiling.
    ///
    /// The derived ceiling is a conservative structural upper bound over
    /// every value permitted by the supplied limits. JSON strings and object
    /// keys are charged at six canonical bytes per UTF-8 input byte plus
    /// quotes, covering the longest JCS escape (`\u00xx`). Object members and
    /// array elements are recursively charged through `maximum_depth`.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedJsonDescriptorError`] if a limit is unsupported or
    /// if the complete upper-bound calculation overflows `u64`.
    pub fn new(
        maximum_depth: u16,
        maximum_properties_per_object: u32,
        maximum_array_items: u32,
        maximum_key_utf8_bytes: u64,
        maximum_string_utf8_bytes: u64,
        maximum_integer_decimal_width: u8,
    ) -> Result<Self, BoundedJsonDescriptorError> {
        validate_descriptor_limits(maximum_depth, maximum_integer_decimal_width)?;
        let maximum_canonical_bytes = calculate_maximum_canonical_bytes(
            maximum_depth,
            maximum_properties_per_object,
            maximum_array_items,
            maximum_key_utf8_bytes,
            maximum_string_utf8_bytes,
            maximum_integer_decimal_width,
        )?;

        Ok(Self {
            canonical_bytes: maximum_canonical_bytes,
            depth: maximum_depth,
            properties_per_object: maximum_properties_per_object,
            array_items: maximum_array_items,
            key_utf8_bytes: maximum_key_utf8_bytes,
            string_utf8_bytes: maximum_string_utf8_bytes,
            integer_decimal_width: maximum_integer_decimal_width,
        })
    }

    /// Returns the pre-effect maximum canonical byte length.
    #[must_use]
    pub const fn maximum_canonical_bytes(&self) -> u64 {
        self.canonical_bytes
    }

    /// Returns the maximum nesting depth, counting the root as depth one.
    #[must_use]
    pub const fn maximum_depth(&self) -> u16 {
        self.depth
    }

    /// Returns the maximum number of properties in any object.
    #[must_use]
    pub const fn maximum_properties_per_object(&self) -> u32 {
        self.properties_per_object
    }

    /// Returns the maximum number of items in any array.
    #[must_use]
    pub const fn maximum_array_items(&self) -> u32 {
        self.array_items
    }

    /// Returns the maximum UTF-8 byte length of any object key.
    #[must_use]
    pub const fn maximum_key_utf8_bytes(&self) -> u64 {
        self.key_utf8_bytes
    }

    /// Returns the maximum UTF-8 byte length of any string value.
    #[must_use]
    pub const fn maximum_string_utf8_bytes(&self) -> u64 {
        self.string_utf8_bytes
    }

    /// Returns the maximum canonical decimal width of any integer.
    #[must_use]
    pub const fn maximum_integer_decimal_width(&self) -> u8 {
        self.integer_decimal_width
    }

    /// Validates one observed JSON value without changing the descriptor.
    ///
    /// Validation checks every structural limit, rejects floating-point and
    /// out-of-range integer values, serializes with NQ's production JCS
    /// implementation, and checks the resulting exact length against the
    /// independently derived pre-effect ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedJsonError`] at the first unsupported or out-of-bound
    /// value.
    pub fn validate(&self, value: &Value) -> Result<(), BoundedJsonError> {
        validate_value(self, value, 1)?;
        let canonical = canonical_json_bytes(value)?;
        let actual = u64::try_from(canonical.len())
            .map_err(|_| BoundedJsonError::CanonicalLengthUnrepresentable)?;
        if actual > self.canonical_bytes {
            return Err(BoundedJsonError::CanonicalBytesExceeded {
                actual,
                maximum: self.canonical_bytes,
            });
        }
        Ok(())
    }

    /// Validates and returns the exact production-canonical bytes.
    ///
    /// The returned observed length is evidence about this value only. It must
    /// not be used to enlarge or select a pre-effect reservation.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedJsonError`] under the same conditions as
    /// [`Self::validate`].
    pub fn canonical_bytes(&self, value: &Value) -> Result<Vec<u8>, BoundedJsonError> {
        validate_value(self, value, 1)?;
        let canonical = canonical_json_bytes(value)?;
        let actual = u64::try_from(canonical.len())
            .map_err(|_| BoundedJsonError::CanonicalLengthUnrepresentable)?;
        if actual > self.canonical_bytes {
            return Err(BoundedJsonError::CanonicalBytesExceeded {
                actual,
                maximum: self.canonical_bytes,
            });
        }
        Ok(canonical)
    }
}

impl<'de> Deserialize<'de> for BoundedJsonDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireDescriptor {
            #[serde(rename = "maximum_canonical_bytes")]
            canonical_bytes: u64,
            #[serde(rename = "maximum_depth")]
            depth: u16,
            #[serde(rename = "maximum_properties_per_object")]
            properties_per_object: u32,
            #[serde(rename = "maximum_array_items")]
            array_items: u32,
            #[serde(rename = "maximum_key_utf8_bytes")]
            key_utf8_bytes: u64,
            #[serde(rename = "maximum_string_utf8_bytes")]
            string_utf8_bytes: u64,
            #[serde(rename = "maximum_integer_decimal_width")]
            integer_decimal_width: u8,
        }

        let wire = WireDescriptor::deserialize(deserializer)?;
        let descriptor = Self::new(
            wire.depth,
            wire.properties_per_object,
            wire.array_items,
            wire.key_utf8_bytes,
            wire.string_utf8_bytes,
            wire.integer_decimal_width,
        )
        .map_err(D::Error::custom)?;
        if descriptor.canonical_bytes != wire.canonical_bytes {
            return Err(D::Error::custom(
                BoundedJsonDescriptorError::CanonicalByteBoundMismatch {
                    declared: wire.canonical_bytes,
                    derived: descriptor.canonical_bytes,
                },
            ));
        }
        Ok(descriptor)
    }
}

/// Failure to construct or decode a bounded-JSON descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BoundedJsonDescriptorError {
    /// A JSON value cannot have a zero root depth.
    #[error("maximum JSON depth must be at least one")]
    ZeroDepth,
    /// Descriptor depth exceeds the construction-time safety limit.
    #[error("maximum JSON depth {actual} exceeds supported limit {maximum}")]
    DepthUnsupported {
        /// Declared maximum depth.
        actual: u16,
        /// Largest supported maximum depth.
        maximum: u16,
    },
    /// An integer decimal width must include at least one digit.
    #[error("maximum integer decimal width must be at least one")]
    ZeroIntegerDecimalWidth,
    /// Integer width exceeds the exact I-JSON/JCS integer model.
    #[error(
        "maximum integer decimal width {actual} exceeds exact I-JSON limit {maximum}; use a typed decimal string"
    )]
    IntegerDecimalWidthUnsupported {
        /// Declared decimal width.
        actual: u8,
        /// Largest supported decimal width.
        maximum: u8,
    },
    /// Checked calculation of the structural bound overflowed.
    #[error("bounded canonical JSON size calculation overflowed")]
    ArithmeticOverflow,
    /// Serialized descriptor carried a byte bound not derived from its limits.
    #[error("declared canonical JSON byte bound {declared} does not equal derived bound {derived}")]
    CanonicalByteBoundMismatch {
        /// Byte bound found in serialized material.
        declared: u64,
        /// Byte bound derived from all other fields.
        derived: u64,
    },
}

/// Failure to validate an observed JSON value against a pre-effect descriptor.
#[derive(Debug, Error)]
pub enum BoundedJsonError {
    /// A nested value exceeds the declared root-relative depth.
    #[error("JSON depth {actual} exceeds maximum {maximum}")]
    DepthExceeded {
        /// Observed root-relative depth.
        actual: u16,
        /// Declared maximum depth.
        maximum: u16,
    },
    /// An object has too many properties.
    #[error("JSON object has {actual} properties; maximum is {maximum}")]
    ObjectPropertiesExceeded {
        /// Observed property count.
        actual: u64,
        /// Declared maximum property count.
        maximum: u32,
    },
    /// An array has too many items.
    #[error("JSON array has {actual} items; maximum is {maximum}")]
    ArrayItemsExceeded {
        /// Observed item count.
        actual: u64,
        /// Declared maximum item count.
        maximum: u32,
    },
    /// An object key is too large in its admitted UTF-8 representation.
    #[error("JSON object key has {actual} UTF-8 bytes; maximum is {maximum}")]
    KeyUtf8BytesExceeded {
        /// Observed UTF-8 byte length.
        actual: u64,
        /// Declared maximum UTF-8 byte length.
        maximum: u64,
    },
    /// A string is too large in its admitted UTF-8 representation.
    #[error("JSON string has {actual} UTF-8 bytes; maximum is {maximum}")]
    StringUtf8BytesExceeded {
        /// Observed UTF-8 byte length.
        actual: u64,
        /// Declared maximum UTF-8 byte length.
        maximum: u64,
    },
    /// An integer is wider than the descriptor permits.
    #[error("JSON integer has canonical width {actual}; maximum is {maximum}")]
    IntegerDecimalWidthExceeded {
        /// Observed canonical decimal width.
        actual: u64,
        /// Declared maximum canonical decimal width.
        maximum: u8,
    },
    /// A JSON number is not an integer.
    #[error(
        "floating-point JSON number `{representation}` is unsupported by bounded canonical JSON"
    )]
    FloatingPointUnsupported {
        /// Original JSON number representation.
        representation: String,
    },
    /// An integer is outside the exact I-JSON number range.
    #[error(
        "JSON integer `{representation}` exceeds the exact I-JSON range; use a typed decimal string"
    )]
    IntegerOutsideExactRange {
        /// Original JSON number representation.
        representation: String,
    },
    /// Production canonicalization failed.
    #[error(transparent)]
    Canonicalization(#[from] CanonicalizationError),
    /// The canonical serializer returned a length not representable by `u64`.
    #[error("canonical JSON length cannot be represented by the descriptor")]
    CanonicalLengthUnrepresentable,
    /// Defense-in-depth check found bytes beyond the pre-effect bound.
    #[error("canonical JSON has {actual} bytes; pre-effect maximum is {maximum}")]
    CanonicalBytesExceeded {
        /// Observed exact canonical byte length.
        actual: u64,
        /// Pre-effect maximum canonical byte length.
        maximum: u64,
    },
}

fn validate_descriptor_limits(
    maximum_depth: u16,
    maximum_integer_decimal_width: u8,
) -> Result<(), BoundedJsonDescriptorError> {
    if maximum_depth == 0 {
        return Err(BoundedJsonDescriptorError::ZeroDepth);
    }
    if maximum_depth > MAX_BOUNDED_JSON_DEPTH {
        return Err(BoundedJsonDescriptorError::DepthUnsupported {
            actual: maximum_depth,
            maximum: MAX_BOUNDED_JSON_DEPTH,
        });
    }
    if maximum_integer_decimal_width == 0 {
        return Err(BoundedJsonDescriptorError::ZeroIntegerDecimalWidth);
    }
    if maximum_integer_decimal_width > MAX_I_JSON_INTEGER_DECIMAL_WIDTH {
        return Err(BoundedJsonDescriptorError::IntegerDecimalWidthUnsupported {
            actual: maximum_integer_decimal_width,
            maximum: MAX_I_JSON_INTEGER_DECIMAL_WIDTH,
        });
    }
    Ok(())
}

fn calculate_maximum_canonical_bytes(
    maximum_depth: u16,
    maximum_properties_per_object: u32,
    maximum_array_items: u32,
    maximum_key_utf8_bytes: u64,
    maximum_string_utf8_bytes: u64,
    maximum_integer_decimal_width: u8,
) -> Result<u64, BoundedJsonDescriptorError> {
    let key = maximum_escaped_string_bytes(maximum_key_utf8_bytes)?;
    let string = maximum_escaped_string_bytes(maximum_string_utf8_bytes)?;
    let scalar = 5_u64
        .max(string)
        .max(u64::from(maximum_integer_decimal_width));

    // At the deepest allowed level, a scalar or an empty container is valid.
    let mut child_bound = scalar.max(2);
    for _ in 1..maximum_depth {
        let array_bound =
            delimited_collection_bound(u64::from(maximum_array_items), child_bound, 0)?;
        let object_bound = delimited_collection_bound(
            u64::from(maximum_properties_per_object),
            child_bound,
            key.checked_add(1)
                .ok_or(BoundedJsonDescriptorError::ArithmeticOverflow)?,
        )?;
        child_bound = child_bound.max(array_bound).max(object_bound);
    }
    Ok(child_bound)
}

fn maximum_escaped_string_bytes(
    maximum_utf8_bytes: u64,
) -> Result<u64, BoundedJsonDescriptorError> {
    maximum_utf8_bytes
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(2))
        .ok_or(BoundedJsonDescriptorError::ArithmeticOverflow)
}

fn delimited_collection_bound(
    count: u64,
    child_bound: u64,
    per_child_prefix: u64,
) -> Result<u64, BoundedJsonDescriptorError> {
    if count == 0 {
        return Ok(2);
    }
    let member = per_child_prefix
        .checked_add(child_bound)
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or(BoundedJsonDescriptorError::ArithmeticOverflow)?;
    count
        .checked_mul(member)
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or(BoundedJsonDescriptorError::ArithmeticOverflow)
}

fn validate_value(
    descriptor: &BoundedJsonDescriptor,
    value: &Value,
    depth: u16,
) -> Result<(), BoundedJsonError> {
    if depth > descriptor.depth {
        return Err(BoundedJsonError::DepthExceeded {
            actual: depth,
            maximum: descriptor.depth,
        });
    }

    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => validate_number(descriptor, number),
        Value::String(string) => {
            let actual = u64::try_from(string.len())
                .map_err(|_| BoundedJsonError::CanonicalLengthUnrepresentable)?;
            if actual > descriptor.string_utf8_bytes {
                return Err(BoundedJsonError::StringUtf8BytesExceeded {
                    actual,
                    maximum: descriptor.string_utf8_bytes,
                });
            }
            Ok(())
        }
        Value::Array(values) => {
            let actual = u64::try_from(values.len())
                .map_err(|_| BoundedJsonError::CanonicalLengthUnrepresentable)?;
            if actual > u64::from(descriptor.array_items) {
                return Err(BoundedJsonError::ArrayItemsExceeded {
                    actual,
                    maximum: descriptor.array_items,
                });
            }
            let child_depth = depth
                .checked_add(1)
                .ok_or(BoundedJsonError::DepthExceeded {
                    actual: u16::MAX,
                    maximum: descriptor.depth,
                })?;
            for child in values {
                validate_value(descriptor, child, child_depth)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            let actual = u64::try_from(object.len())
                .map_err(|_| BoundedJsonError::CanonicalLengthUnrepresentable)?;
            if actual > u64::from(descriptor.properties_per_object) {
                return Err(BoundedJsonError::ObjectPropertiesExceeded {
                    actual,
                    maximum: descriptor.properties_per_object,
                });
            }
            let child_depth = depth
                .checked_add(1)
                .ok_or(BoundedJsonError::DepthExceeded {
                    actual: u16::MAX,
                    maximum: descriptor.depth,
                })?;
            for (key, child) in object {
                let key_bytes = u64::try_from(key.len())
                    .map_err(|_| BoundedJsonError::CanonicalLengthUnrepresentable)?;
                if key_bytes > descriptor.key_utf8_bytes {
                    return Err(BoundedJsonError::KeyUtf8BytesExceeded {
                        actual: key_bytes,
                        maximum: descriptor.key_utf8_bytes,
                    });
                }
                validate_value(descriptor, child, child_depth)?;
            }
            Ok(())
        }
    }
}

fn validate_number(
    descriptor: &BoundedJsonDescriptor,
    number: &serde_json::Number,
) -> Result<(), BoundedJsonError> {
    let representation = number.to_string();
    let in_exact_range = if number.is_i64() {
        number.as_i64().is_some_and(|integer| {
            (-MAX_EXACT_I_JSON_INTEGER..=MAX_EXACT_I_JSON_INTEGER).contains(&integer)
        })
    } else if number.is_u64() {
        number
            .as_u64()
            .is_some_and(|integer| integer <= MAX_EXACT_I_JSON_INTEGER as u64)
    } else {
        return Err(BoundedJsonError::FloatingPointUnsupported { representation });
    };

    if !in_exact_range {
        return Err(BoundedJsonError::IntegerOutsideExactRange { representation });
    }
    let actual = u64::try_from(representation.len())
        .map_err(|_| BoundedJsonError::CanonicalLengthUnrepresentable)?;
    if actual > u64::from(descriptor.integer_decimal_width) {
        return Err(BoundedJsonError::IntegerDecimalWidthExceeded {
            actual,
            maximum: descriptor.integer_decimal_width,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Number, json};

    use super::*;

    fn descriptor() -> BoundedJsonDescriptor {
        BoundedJsonDescriptor::new(2, 4, 3, 2, 2, 3).expect("bounded descriptor")
    }

    #[test]
    fn derives_pre_effect_bound_and_accepts_exact_maximal_escape_witness() {
        let descriptor = descriptor();
        assert_eq!(descriptor.maximum_canonical_bytes(), 121);

        let value = Value::Object(Map::from_iter([
            ("\0\0".to_owned(), Value::String("\0\0".to_owned())),
            ("\0\u{1}".to_owned(), Value::String("\0\0".to_owned())),
            ("\0\u{2}".to_owned(), Value::String("\0\0".to_owned())),
            ("\0\u{3}".to_owned(), Value::String("\0\0".to_owned())),
        ]));
        let canonical = descriptor.canonical_bytes(&value).expect("exact witness");
        assert_eq!(canonical.len(), 121);
        assert_eq!(
            u64::try_from(canonical.len()).unwrap(),
            descriptor.maximum_canonical_bytes()
        );
    }

    #[test]
    fn actual_validation_is_separate_and_cannot_change_bound() {
        let descriptor = descriptor();
        let before = descriptor.clone();
        descriptor.validate(&json!({"ok": 1})).expect("value fits");
        assert_eq!(descriptor, before);
        assert_eq!(descriptor.maximum_canonical_bytes(), 121);
    }

    #[test]
    fn uses_production_jcs_ordering() {
        let descriptor = BoundedJsonDescriptor::new(2, 2, 0, 1, 0, 1).expect("bounded descriptor");
        assert_eq!(
            descriptor
                .canonical_bytes(&json!({"b": null, "a": true}))
                .expect("canonical bounded JSON"),
            br#"{"a":true,"b":null}"#
        );
    }

    #[test]
    fn refuses_each_structural_boundary() {
        let descriptor = BoundedJsonDescriptor::new(2, 1, 1, 1, 1, 2).unwrap();

        assert!(matches!(
            descriptor.validate(&json!({"a": {"b": 1}})),
            Err(BoundedJsonError::DepthExceeded { .. })
        ));
        assert!(matches!(
            descriptor.validate(&json!({"a": 1, "b": 2})),
            Err(BoundedJsonError::ObjectPropertiesExceeded { .. })
        ));
        assert!(matches!(
            descriptor.validate(&json!([1, 2])),
            Err(BoundedJsonError::ArrayItemsExceeded { .. })
        ));
        assert!(matches!(
            descriptor.validate(&json!({"ab": 1})),
            Err(BoundedJsonError::KeyUtf8BytesExceeded { .. })
        ));
        assert!(matches!(
            descriptor.validate(&json!("ab")),
            Err(BoundedJsonError::StringUtf8BytesExceeded { .. })
        ));
        assert!(matches!(
            descriptor.validate(&json!(-12)),
            Err(BoundedJsonError::IntegerDecimalWidthExceeded { .. })
        ));
    }

    #[test]
    fn empty_containers_fit_at_the_depth_boundary() {
        let descriptor = BoundedJsonDescriptor::new(1, 0, 0, 0, 0, 1).unwrap();
        descriptor.validate(&json!({})).expect("empty object");
        descriptor.validate(&json!([])).expect("empty array");
        assert!(matches!(
            descriptor.validate(&json!([null])),
            Err(BoundedJsonError::ArrayItemsExceeded { .. })
        ));
    }

    #[test]
    fn refuses_floats_and_non_exact_integers() {
        let descriptor = BoundedJsonDescriptor::new(1, 0, 0, 0, 0, 17).expect("bounded descriptor");
        assert!(matches!(
            descriptor.validate(&Value::Number(Number::from_f64(1.5).unwrap())),
            Err(BoundedJsonError::FloatingPointUnsupported { .. })
        ));
        let unsafe_integer = descriptor
            .validate(&json!(9_007_199_254_740_992_u64))
            .expect_err("unsafe integer must refuse");
        assert!(
            matches!(
                &unsafe_integer,
                BoundedJsonError::IntegerOutsideExactRange { .. }
            ),
            "unexpected error: {unsafe_integer:?}"
        );
        descriptor
            .validate(&json!(-9_007_199_254_740_991_i64))
            .expect("widest exact integer");
    }

    #[test]
    fn descriptor_construction_is_checked_and_bounded() {
        assert!(matches!(
            BoundedJsonDescriptor::new(0, 0, 0, 0, 0, 1),
            Err(BoundedJsonDescriptorError::ZeroDepth)
        ));
        assert!(matches!(
            BoundedJsonDescriptor::new(MAX_BOUNDED_JSON_DEPTH + 1, 0, 0, 0, 0, 1),
            Err(BoundedJsonDescriptorError::DepthUnsupported { .. })
        ));
        assert!(matches!(
            BoundedJsonDescriptor::new(1, 0, 0, 0, 0, 0),
            Err(BoundedJsonDescriptorError::ZeroIntegerDecimalWidth)
        ));
        assert!(matches!(
            BoundedJsonDescriptor::new(1, 0, 0, 0, 0, MAX_I_JSON_INTEGER_DECIMAL_WIDTH + 1,),
            Err(BoundedJsonDescriptorError::IntegerDecimalWidthUnsupported { .. })
        ));
        assert!(matches!(
            BoundedJsonDescriptor::new(1, 0, 0, 0, u64::MAX, 1),
            Err(BoundedJsonDescriptorError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn serialized_bound_is_derived_not_caller_mintable() {
        let descriptor = descriptor();
        let encoded = serde_json::to_value(&descriptor).expect("serialize descriptor");
        assert_eq!(
            serde_json::from_value::<BoundedJsonDescriptor>(encoded.clone()).unwrap(),
            descriptor
        );

        let mut substituted = encoded;
        substituted["maximum_canonical_bytes"] = json!(120);
        let error = serde_json::from_value::<BoundedJsonDescriptor>(substituted)
            .expect_err("substituted bound must refuse");
        assert!(error.to_string().contains("does not equal derived bound"));
    }
}
