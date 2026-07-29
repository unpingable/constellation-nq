//! Fail-closed execution of the embedded JSON Schema contract.

use std::sync::OnceLock;

use chrono::DateTime;
use serde_json::Value;

use crate::{ContractError, Result, RuntimeSchema, assets::embedded_schema_bytes};

const COMMON_SCHEMA: &str = "nq.host_role_common.v1";

/// Validates one carrier against the exact embedded schema asset.
pub(crate) fn validate(schema: RuntimeSchema, value: &Value) -> Result<()> {
    let root = schema_value(schema.as_str())?;
    let common = schema_value(COMMON_SCHEMA)?;
    Validator {
        common,
        runtime_schema: schema,
    }
    .validate_at(value, root, root, "$")
    .map_err(|detail| ContractError::SchemaValidation { schema, detail })
}

fn schema_value(schema: &str) -> Result<&'static Value> {
    macro_rules! cached {
        ($slot:ident, $schema:expr) => {{
            static $slot: OnceLock<Value> = OnceLock::new();
            if let Some(value) = $slot.get() {
                Ok(value)
            } else {
                let bytes = embedded_schema_bytes($schema)
                    .ok_or_else(|| ContractError::MissingSchemaAsset($schema.to_owned()))?;
                let parsed = serde_json::from_slice(bytes).map_err(ContractError::from)?;
                let _ = $slot.set(parsed);
                Ok($slot
                    .get()
                    .expect("embedded schema cache initialized by this call"))
            }
        }};
    }
    match schema {
        "nq.host_role_common.v1" => cached!(COMMON, "nq.host_role_common.v1"),
        "nq.role_manifest.v1" => cached!(ROLE, "nq.role_manifest.v1"),
        "nq.buffer_delivery_policy.v1" => {
            cached!(BUFFER, "nq.buffer_delivery_policy.v1")
        }
        "nq.static_profile_cohort_manifest.v1" => {
            cached!(COHORT, "nq.static_profile_cohort_manifest.v1")
        }
        "nq.node_enrollment.v1" => cached!(ENROLLMENT, "nq.node_enrollment.v1"),
        "nq.host_role_relation.v1" => cached!(RELATION, "nq.host_role_relation.v1"),
        "nq.runtime_activation.v1" => cached!(ACTIVATION, "nq.runtime_activation.v1"),
        "nq.witness_attachment.v1" => {
            cached!(ATTACHMENT, "nq.witness_attachment.v1")
        }
        "nq.host_role_lifecycle_event.v1" => {
            cached!(HOST_EVENT, "nq.host_role_lifecycle_event.v1")
        }
        "nq.witness_lifecycle_event.v1" => {
            cached!(WITNESS_EVENT, "nq.witness_lifecycle_event.v1")
        }
        "nq.node_key_lifecycle_event.v1" => {
            cached!(KEY_EVENT, "nq.node_key_lifecycle_event.v1")
        }
        "nq.restore_activation_proof.v1" => {
            cached!(RESTORE, "nq.restore_activation_proof.v1")
        }
        "nq.diagnostic_invocation_request.v1" => {
            cached!(REQUEST, "nq.diagnostic_invocation_request.v1")
        }
        "nq.invocation_decision.v1" => {
            cached!(DECISION, "nq.invocation_decision.v1")
        }
        "nq.operation_authorization.v1" => {
            cached!(AUTHORIZATION, "nq.operation_authorization.v1")
        }
        "nq.custody_reservation.v1" => {
            cached!(RESERVATION, "nq.custody_reservation.v1")
        }
        "nq.execution_launch.v1" => cached!(LAUNCH, "nq.execution_launch.v1"),
        "nq.execution_identity_binding.v2" => {
            cached!(BINDING, "nq.execution_identity_binding.v2")
        }
        "nq.authenticated_artifact_envelope.v1" => {
            cached!(ENVELOPE, "nq.authenticated_artifact_envelope.v1")
        }
        "nq.artifact_delivery_attempt.v1" => {
            cached!(ATTEMPT, "nq.artifact_delivery_attempt.v1")
        }
        "nightshift.artifact_custody_receipt.v1" => {
            cached!(RECEIPT, "nightshift.artifact_custody_receipt.v1")
        }
        "nq.artifact_delivery_record.v1" => {
            cached!(DELIVERY, "nq.artifact_delivery_record.v1")
        }
        "nq.inspector_result_set.v1" => {
            cached!(RESULT_SET, "nq.inspector_result_set.v1")
        }
        "nq.inspector_snapshot.v1" => {
            cached!(INSPECTOR_SNAPSHOT, "nq.inspector_snapshot.v1")
        }
        "nq.inspector_read_receipt.v1" => {
            cached!(READ_RECEIPT, "nq.inspector_read_receipt.v1")
        }
        "nq.decommission_ledger_snapshot.v1" => {
            cached!(DECOMMISSION_SNAPSHOT, "nq.decommission_ledger_snapshot.v1")
        }
        "nq.decommission_cut.v1" => cached!(DECOMMISSION_CUT, "nq.decommission_cut.v1"),
        other => Err(ContractError::MissingSchemaAsset(other.to_owned())),
    }
}

struct Validator<'a> {
    common: &'a Value,
    runtime_schema: RuntimeSchema,
}

impl Validator<'_> {
    #[allow(clippy::too_many_lines)]
    fn validate_at(
        &self,
        instance: &Value,
        schema: &Value,
        document: &Value,
        path: &str,
    ) -> std::result::Result<(), String> {
        let object = schema
            .as_object()
            .ok_or_else(|| format!("{path}: schema node is not an object"))?;

        if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
            let (resolved, resolved_document) = self.resolve_reference(reference, document)?;
            self.validate_at(instance, resolved, resolved_document, path)?;
        }
        if let Some(expected_type) = object.get("type").and_then(Value::as_str) {
            let valid = match expected_type {
                "object" => instance.is_object(),
                "array" => instance.is_array(),
                "string" => instance.is_string(),
                "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
                "boolean" => instance.is_boolean(),
                "null" => instance.is_null(),
                other => {
                    return Err(format!(
                        "{path}: unsupported embedded schema type {other} in {:?}",
                        self.runtime_schema
                    ));
                }
            };
            if !valid {
                return Err(format!("{path}: expected {expected_type}"));
            }
        }
        if object
            .get("const")
            .is_some_and(|expected| instance != expected)
        {
            return Err(format!("{path}: const mismatch"));
        }
        if object
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|options| !options.contains(instance))
        {
            return Err(format!("{path}: value outside closed enum"));
        }

        if let Some(text) = instance.as_str() {
            Self::validate_string(text, object, path)?;
        }
        if let Some(integer) = instance.as_i64() {
            Self::validate_integer(i128::from(integer), object, path)?;
        } else if let Some(integer) = instance.as_u64() {
            Self::validate_integer(i128::from(integer), object, path)?;
        }
        if let Some(array) = instance.as_array() {
            self.validate_array(array, object, document, path)?;
        }
        if let Some(instance_object) = instance.as_object() {
            self.validate_object(instance_object, object, document, path)?;
        }

        if let Some(all_of) = object.get("allOf").and_then(Value::as_array) {
            for child in all_of {
                self.validate_at(instance, child, document, path)?;
            }
        }
        if let Some(one_of) = object.get("oneOf").and_then(Value::as_array) {
            let matches = one_of
                .iter()
                .filter(|candidate| {
                    self.validate_at(instance, candidate, document, path)
                        .is_ok()
                })
                .count();
            if matches != 1 {
                return Err(format!(
                    "{path}: expected exactly one oneOf branch, got {matches}"
                ));
            }
        }
        if let Some(condition) = object.get("if") {
            if self
                .validate_at(instance, condition, document, path)
                .is_ok()
            {
                if let Some(consequence) = object.get("then") {
                    self.validate_at(instance, consequence, document, path)?;
                }
            } else if let Some(alternative) = object.get("else") {
                self.validate_at(instance, alternative, document, path)?;
            }
        }
        Ok(())
    }

    fn resolve_reference<'a>(
        &'a self,
        reference: &str,
        current_document: &'a Value,
    ) -> std::result::Result<(&'a Value, &'a Value), String> {
        let (document, fragment) = if let Some(fragment) = reference.strip_prefix('#') {
            (current_document, fragment)
        } else if let Some(fragment) = reference.strip_prefix("nq.host_role_common.v1.schema.json#")
        {
            (self.common, fragment)
        } else {
            return Err(format!("unsupported embedded schema reference {reference}"));
        };
        if fragment.is_empty() {
            Ok((document, document))
        } else {
            document
                .pointer(fragment)
                .map(|resolved| (resolved, document))
                .ok_or_else(|| format!("unresolved embedded schema reference {reference}"))
        }
    }

    fn validate_string(
        text: &str,
        schema: &serde_json::Map<String, Value>,
        path: &str,
    ) -> std::result::Result<(), String> {
        let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| length < minimum)
        {
            return Err(format!("{path}: string shorter than minLength"));
        }
        if schema
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| length > maximum)
        {
            return Err(format!("{path}: string longer than maxLength"));
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str)
            && !known_pattern_matches(pattern, text)
        {
            return Err(format!("{path}: string does not match {pattern}"));
        }
        if schema.get("format").and_then(Value::as_str) == Some("date-time")
            && DateTime::parse_from_rfc3339(text).is_err()
        {
            return Err(format!("{path}: invalid RFC 3339 date-time"));
        }
        Ok(())
    }

    fn validate_integer(
        integer: i128,
        schema: &serde_json::Map<String, Value>,
        path: &str,
    ) -> std::result::Result<(), String> {
        if schema
            .get("minimum")
            .and_then(Value::as_i64)
            .is_some_and(|minimum| integer < i128::from(minimum))
        {
            return Err(format!("{path}: integer below minimum"));
        }
        if schema
            .get("maximum")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| integer > i128::from(maximum))
        {
            return Err(format!("{path}: integer above maximum"));
        }
        Ok(())
    }

    fn validate_array(
        &self,
        array: &[Value],
        schema: &serde_json::Map<String, Value>,
        document: &Value,
        path: &str,
    ) -> std::result::Result<(), String> {
        let length = u64::try_from(array.len()).unwrap_or(u64::MAX);
        if schema
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| length < minimum)
        {
            return Err(format!("{path}: array shorter than minItems"));
        }
        if schema
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| length > maximum)
        {
            return Err(format!("{path}: array longer than maxItems"));
        }
        if schema.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
            for (index, item) in array.iter().enumerate() {
                if array[..index].contains(item) {
                    return Err(format!("{path}: array violates uniqueItems"));
                }
            }
        }
        let prefix_count = if let Some(prefix) = schema.get("prefixItems").and_then(Value::as_array)
        {
            for (index, child_schema) in prefix.iter().enumerate() {
                if let Some(child) = array.get(index) {
                    self.validate_at(child, child_schema, document, &format!("{path}/{index}"))?;
                }
            }
            prefix.len()
        } else {
            0
        };
        if let Some(item_schema) = schema.get("items") {
            for (index, child) in array.iter().enumerate().skip(prefix_count) {
                self.validate_at(child, item_schema, document, &format!("{path}/{index}"))?;
            }
        }
        Ok(())
    }

    fn validate_object(
        &self,
        instance: &serde_json::Map<String, Value>,
        schema: &serde_json::Map<String, Value>,
        document: &Value,
        path: &str,
    ) -> std::result::Result<(), String> {
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required {
                let field = field
                    .as_str()
                    .ok_or_else(|| format!("{path}: invalid required-field schema"))?;
                if !instance.contains_key(field) {
                    return Err(format!("{path}: missing required field {field}"));
                }
            }
        }
        if let Some(properties) = properties {
            for (field, child_schema) in properties {
                if let Some(child) = instance.get(field) {
                    self.validate_at(
                        child,
                        child_schema,
                        document,
                        &format!("{path}/{}", escape_pointer(field)),
                    )?;
                }
            }
            if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false) {
                for field in instance.keys() {
                    if !properties.contains_key(field) {
                        return Err(format!("{path}: unknown field {field}"));
                    }
                }
            }
        }
        Ok(())
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn known_pattern_matches(pattern: &str, text: &str) -> bool {
    match pattern {
        "^sha256:[0-9a-f]{64}$" => text.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }),
        "^[1-9][0-9]*$" => {
            !text.starts_with('0')
                && text.bytes().all(|byte| byte.is_ascii_digit())
                && !text.is_empty()
        }
        "^[A-Za-z0-9._:/@+-]+$" => {
            !text.is_empty()
                && text.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
                })
        }
        "^[a-z][a-z0-9_]*$" => {
            text.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        }
        "^[a-z0-9._-]+(?:/[a-z0-9._-]+)*$" => {
            !text.is_empty()
                && text.split('/').all(|component| {
                    !component.is_empty()
                        && component.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'.' | b'_' | b'-')
                        })
                })
        }
        "^(|/.*)$" => text.is_empty() || text.starts_with('/'),
        "^/" => text.starts_with('/'),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::{COMMON_SCHEMA, known_pattern_matches, schema_value};
    use crate::RuntimeSchema;

    const SUPPORTED_KEYWORDS: [&str; 27] = [
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "const",
        "else",
        "enum",
        "format",
        "if",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "oneOf",
        "pattern",
        "prefixItems",
        "properties",
        "required",
        "then",
        "title",
        "type",
        "uniqueItems",
    ];

    #[test]
    fn embedded_schema_vocabulary_cannot_silently_outrun_the_executor() {
        let mut schemas = RuntimeSchema::ALL
            .into_iter()
            .map(RuntimeSchema::as_str)
            .collect::<Vec<_>>();
        schemas.push(COMMON_SCHEMA);
        for name in schemas {
            audit_schema_node(schema_value(name).expect("embedded schema"), "$");
        }
    }

    fn audit_schema_node(schema: &Value, path: &str) {
        let object = schema
            .as_object()
            .unwrap_or_else(|| panic!("{path}: schema node is not an object"));
        let supported = BTreeSet::from(SUPPORTED_KEYWORDS);
        for keyword in object.keys() {
            assert!(
                supported.contains(keyword.as_str()),
                "{path}: unsupported JSON Schema keyword {keyword}"
            );
        }
        if let Some(pattern) = object.get("pattern").and_then(Value::as_str) {
            // The matcher returns false for unknown patterns, including against
            // a deliberately valid-looking probe string.
            assert!(
                known_pattern_matches(pattern, "a")
                    || matches!(
                        pattern,
                        "^sha256:[0-9a-f]{64}$" | "^[1-9][0-9]*$" | "^(|/.*)$" | "^/"
                    ),
                "{path}: unsupported regex pattern {pattern}"
            );
        }
        if let Some(format) = object.get("format").and_then(Value::as_str) {
            assert_eq!(format, "date-time", "{path}: unsupported format");
        }
        if let Some(definitions) = object.get("$defs").and_then(Value::as_object) {
            for (name, child) in definitions {
                audit_schema_node(child, &format!("{path}/$defs/{name}"));
            }
        }
        if let Some(properties) = object.get("properties").and_then(Value::as_object) {
            for (name, child) in properties {
                audit_schema_node(child, &format!("{path}/properties/{name}"));
            }
        }
        for keyword in ["allOf", "oneOf", "prefixItems"] {
            if let Some(children) = object.get(keyword).and_then(Value::as_array) {
                for (index, child) in children.iter().enumerate() {
                    audit_schema_node(child, &format!("{path}/{keyword}/{index}"));
                }
            }
        }
        for keyword in ["if", "then", "else", "items"] {
            if let Some(child) = object.get(keyword) {
                audit_schema_node(child, &format!("{path}/{keyword}"));
            }
        }
    }
}
