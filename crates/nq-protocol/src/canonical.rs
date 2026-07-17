use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Failure to convert a serializable value into canonical NQ JSON.
#[derive(Debug, Error)]
pub enum CanonicalizationError {
    /// Serialization itself failed.
    #[error("cannot canonicalize JSON: {0}")]
    Serialization(#[from] serde_json::Error),
    /// An integer could not be represented exactly by the I-JSON/JCS number
    /// model and must instead be modeled as a decimal string.
    #[error("integer {0} exceeds the exact I-JSON range; encode it as a decimal string")]
    UnsafeInteger(String),
}

/// A lowercase, algorithm-qualified SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Parses `sha256:` followed by exactly 64 lowercase hexadecimal digits.
    ///
    /// # Errors
    ///
    /// Returns [`DigestParseError`] if the algorithm prefix, length, case, or
    /// hexadecimal alphabet is not exact.
    pub fn parse(value: impl Into<String>) -> Result<Self, DigestParseError> {
        let value = value.into();
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(DigestParseError);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DigestParseError);
        }
        Ok(Self(value))
    }

    /// Returns the algorithm-qualified digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes this digest and returns its text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Error returned for a malformed SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("digest must be `sha256:` followed by 64 lowercase hexadecimal digits")]
pub struct DigestParseError;

/// Serializes a value as RFC 8785 JSON Canonicalization Scheme (JCS) bytes.
///
/// The result is deterministic compact UTF-8 JSON and contains no trailing
/// newline. JCS defines UTF-16 object-key ordering, ECMAScript-compatible
/// finite-number rendering, and exact string escaping across implementations.
///
/// # Errors
///
/// Returns [`CanonicalizationError`] if `value` cannot be represented as JSON.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalizationError> {
    let value = serde_json::to_value(value)?;
    validate_i_json_numbers(&value)?;
    serde_jcs::to_vec(&value).map_err(CanonicalizationError::from)
}

fn validate_i_json_numbers(value: &Value) -> Result<(), CanonicalizationError> {
    match value {
        Value::Number(number) if number.is_i64() => {
            let integer = number.as_i64().expect("is_i64 checked");
            if !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&integer) {
                return Err(CanonicalizationError::UnsafeInteger(number.to_string()));
            }
        }
        Value::Number(number) if number.is_u64() => {
            let integer = number.as_u64().expect("is_u64 checked");
            if integer > 9_007_199_254_740_991 {
                return Err(CanonicalizationError::UnsafeInteger(number.to_string()));
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_i_json_numbers(child)?;
            }
        }
        Value::Object(object) => {
            for child in object.values() {
                validate_i_json_numbers(child)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

/// Computes an algorithm-qualified SHA-256 digest of arbitrary bytes.
#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256::digest(bytes);
    Sha256Digest(format!("sha256:{}", hex::encode(digest)))
}

/// Computes the semantic identity of a value's canonical JSON form.
///
/// # Errors
///
/// Returns [`CanonicalizationError`] if `value` cannot be represented as JSON.
pub fn semantic_digest<T: Serialize>(value: &T) -> Result<Sha256Digest, CanonicalizationError> {
    canonical_json_bytes(value).map(|bytes| sha256_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonicalization_sorts_nested_keys() {
        let first = json!({"z": {"b": 2, "a": 1}, "a": [3, 2, 1]});
        let second = json!({"a": [3, 2, 1], "z": {"a": 1, "b": 2}});
        let expected = br#"{"a":[3,2,1],"z":{"a":1,"b":2}}"#;
        assert_eq!(canonical_json_bytes(&first).unwrap(), expected);
        assert_eq!(
            semantic_digest(&first).unwrap(),
            semantic_digest(&second).unwrap()
        );
    }

    #[test]
    fn canonicalization_uses_ecmascript_number_rendering() {
        let value = json!([333_333_333.333_333_3, 1e30, 4.50, 2e-3, 1e-27]);
        assert_eq!(
            canonical_json_bytes(&value).unwrap(),
            br"[333333333.3333333,1e+30,4.5,0.002,1e-27]"
        );
    }

    #[test]
    fn canonicalization_rejects_integers_outside_exact_i_json_range() {
        let value = json!({"counter": u64::MAX});
        assert!(matches!(
            canonical_json_bytes(&value),
            Err(CanonicalizationError::UnsafeInteger(_))
        ));
    }

    #[test]
    fn digest_parser_is_deliberately_strict() {
        assert!(Sha256Digest::parse(format!("sha256:{}", "a".repeat(64))).is_ok());
        assert!(Sha256Digest::parse(format!("sha256:{}", "A".repeat(64))).is_err());
        assert!(Sha256Digest::parse("a".repeat(64)).is_err());
    }
}
