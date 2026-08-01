//! Unambiguous domain-separated framing for identities and signatures.

use nq_protocol::{Sha256Digest, sha256_bytes};

use crate::AuthorityError;

const FRAME_MAGIC: &[u8] = b"NQ-AUTHORITY-FRAME\0";

pub(crate) fn framed_bytes(
    domain: &str,
    version: u16,
    fields: &[(&str, &[u8])],
) -> Result<Vec<u8>, AuthorityError> {
    let mut framed = Vec::new();
    framed.extend_from_slice(FRAME_MAGIC);
    framed.extend_from_slice(&version.to_be_bytes());
    append_u32_len(&mut framed, domain.as_bytes())?;
    let field_count = u32::try_from(fields.len()).map_err(|_| AuthorityError::FramingOverflow)?;
    framed.extend_from_slice(&field_count.to_be_bytes());
    for (label, value) in fields {
        append_u32_len(&mut framed, label.as_bytes())?;
        let value_len = u64::try_from(value.len()).map_err(|_| AuthorityError::FramingOverflow)?;
        framed.extend_from_slice(&value_len.to_be_bytes());
        framed.extend_from_slice(value);
    }
    Ok(framed)
}

pub(crate) fn framed_digest(
    domain: &str,
    version: u16,
    fields: &[(&str, &[u8])],
) -> Result<Sha256Digest, AuthorityError> {
    framed_bytes(domain, version, fields).map(|bytes| sha256_bytes(&bytes))
}

fn append_u32_len(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AuthorityError> {
    let length = u32::try_from(bytes.len()).map_err(|_| AuthorityError::FramingOverflow)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_distinguishes_ambiguous_concatenations() {
        let first = framed_digest("test.domain", 1, &[("a", b"ab"), ("b", b"c")]).unwrap();
        let second = framed_digest("test.domain", 1, &[("a", b"a"), ("b", b"bc")]).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn framing_distinguishes_domain_version_label_and_order() {
        let baseline = framed_digest("test.domain", 1, &[("a", b"x"), ("b", b"y")]).unwrap();
        assert_ne!(
            baseline,
            framed_digest("test.other", 1, &[("a", b"x"), ("b", b"y")]).unwrap()
        );
        assert_ne!(
            baseline,
            framed_digest("test.domain", 2, &[("a", b"x"), ("b", b"y")]).unwrap()
        );
        assert_ne!(
            baseline,
            framed_digest("test.domain", 1, &[("c", b"x"), ("b", b"y")]).unwrap()
        );
        assert_ne!(
            baseline,
            framed_digest("test.domain", 1, &[("b", b"y"), ("a", b"x")]).unwrap()
        );
    }
}
