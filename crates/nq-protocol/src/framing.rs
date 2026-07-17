use std::fmt;

use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use thiserror::Error;

use crate::{
    HelperRequest, HelperResponse, MAX_REQUEST_FRAME_BYTES, ValidationError, canonical_json_bytes,
    validate_exchange, validate_request,
};

/// NDJSON framing, strict decoding, or common validation failure.
#[derive(Debug, Error)]
pub enum FramingError {
    /// A frame exceeded its pre-decode byte limit.
    #[error("frame is {actual} bytes; limit is {limit}")]
    TooLarge {
        /// Permitted maximum including newline.
        limit: usize,
        /// Actual frame size.
        actual: usize,
    },
    /// The exchange did not contain exactly one newline-terminated JSON line.
    #[error("frame must contain exactly one non-empty JSON document followed by LF")]
    NotExactlyOneLine,
    /// JSON was malformed, contained duplicate keys, or failed strict DTO decoding.
    #[error("invalid JSON document: {0}")]
    Json(#[from] serde_json::Error),
    /// Common protocol validation failed after decoding.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// Canonical serialization failed while encoding.
    #[error(transparent)]
    Canonicalization(#[from] crate::CanonicalizationError),
}

/// Encodes one canonical JSON document followed by exactly one LF byte.
///
/// # Errors
///
/// Returns [`FramingError::Canonicalization`] if `value` cannot be represented
/// as JSON.
pub fn encode_ndjson<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, FramingError> {
    let mut bytes = canonical_json_bytes(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Strictly decodes one bounded NDJSON frame and rejects duplicate object keys.
///
/// # Errors
///
/// Returns [`FramingError`] for an oversized or non-canonical frame, malformed
/// JSON, duplicate keys at any depth, or a document that does not match `T`.
pub fn decode_ndjson<T: DeserializeOwned>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, FramingError> {
    if bytes.len() > max_bytes {
        return Err(FramingError::TooLarge {
            limit: max_bytes,
            actual: bytes.len(),
        });
    }
    let Some(body) = bytes.strip_suffix(b"\n") else {
        return Err(FramingError::NotExactlyOneLine);
    };
    if body.is_empty() || body.contains(&b'\n') || body.contains(&b'\r') {
        return Err(FramingError::NotExactlyOneLine);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = NoDuplicateValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    serde_json::from_value(value).map_err(FramingError::Json)
}

/// Decodes and validates one helper request frame.
///
/// # Errors
///
/// Returns [`FramingError`] when framing, strict decoding, or common request
/// validation fails.
pub fn parse_request(bytes: &[u8]) -> Result<HelperRequest, FramingError> {
    let request: HelperRequest = decode_ndjson(bytes, MAX_REQUEST_FRAME_BYTES)?;
    validate_request(&request)?;
    Ok(request)
}

/// Decodes a response under the originating request's exact byte bound and
/// validates the complete exchange.
///
/// # Errors
///
/// Returns [`FramingError`] when framing, strict decoding, response validation,
/// exact echo, identity, capability-subset, or negotiated-bound checks fail.
pub fn parse_response(
    request: &HelperRequest,
    bytes: &[u8],
) -> Result<HelperResponse, FramingError> {
    let response: HelperResponse =
        decode_ndjson(bytes, request.bounds.max_response_bytes as usize)?;
    validate_exchange(request, &response)?;
    Ok(response)
}

struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = NoDuplicateValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(NoDuplicateValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(NoDuplicateValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        NoDuplicateValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<NoDuplicateValue>()? {
            values.push(value.0);
        }
        Ok(NoDuplicateValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format_args!(
                    "duplicate object key {key:?}"
                )));
            }
            let value = object.next_value::<NoDuplicateValue>()?;
            values.insert(key, value.0);
        }
        Ok(NoDuplicateValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn duplicate_keys_are_rejected_at_any_depth() {
        let error = decode_ndjson::<Value>(b"{\"outer\":{\"x\":1,\"x\":2}}\n", 1024)
            .expect_err("duplicate must fail");
        assert!(error.to_string().contains("duplicate object key"));
    }

    #[test]
    fn exactly_one_lf_is_required() {
        assert!(matches!(
            decode_ndjson::<Value>(b"{}", 10),
            Err(FramingError::NotExactlyOneLine)
        ));
        assert!(matches!(
            decode_ndjson::<Value>(b"{}\n{}\n", 10),
            Err(FramingError::NotExactlyOneLine)
        ));
        assert!(decode_ndjson::<Value>(b"{}\n", 10).is_ok());
    }
}
