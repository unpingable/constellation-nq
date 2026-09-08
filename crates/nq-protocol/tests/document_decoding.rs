use nq_protocol::decode_json_document;
use serde_json::{Value, json};

#[test]
fn exact_single_bounded_document_without_key_substitution() {
    assert_eq!(
        decode_json_document::<Value>(b"{\n\"id\": 1\n}\n", 100).unwrap(),
        json!({"id":1})
    );
    for bytes in [
        &b"{\"id\":0,\"id\":1}"[..],
        &b"{\"profiles\":[{\"id\":0,\"id\":1}]}"[..],
        &b"{} {}"[..],
        &b"{\"id\":1} trailing"[..],
    ] {
        assert!(decode_json_document::<Value>(bytes, 100).is_err());
    }
    assert!(decode_json_document::<Value>(b"{}", 1).is_err());
}
