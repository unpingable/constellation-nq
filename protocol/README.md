# Helper protocol v1

This directory is the authoritative, language-neutral helper contract. The
Rust crate in `crates/nq-protocol` implements it; Rust serialization behavior is
not itself the wire specification.

## Exchange

Both one-shot stdio and supervised Unix-socket carriers use the same exchange:

1. NQ sends one UTF-8 JSON document terminated by one LF byte.
2. The helper sends one UTF-8 JSON document terminated by one LF byte.
3. The helper emits no other stdout/socket frames. Bounded diagnostic logs use
   stderr for the stdio carrier.

Pretty-printed JSON, CRLF, missing final LF, multiple lines, duplicate object
keys at any depth, invalid UTF-8, and bytes after the response frame are
protocol failures. A response contains either a report or a refusal. A valid
report whose inner status is `failed` is still testimony; EOF, exit, timeout,
disconnect, and malformed framing create only acquisition/run outcomes.

## Compatibility

- Schema identifiers and `protocol_version` are exact pins, not ranges.
- Receivers reject unknown fields. Adding, removing, renaming, or changing the
  meaning of a field therefore requires a new schema identifier.
- New enum variants require a new schema identifier unless that vocabulary is
  explicitly represented by a validated open token (profile observation,
  coverage, capability, and report-error vocabularies are open tokens).
- Object key order is not significant on input. Array order is significant.
- Responses echo every request-controlled field exactly. Scope, vantage,
  deadline, bounds, and capability grants cannot be widened by a helper.
- A helper declaration, executable digest, backend identity, or successful
  protocol exchange does not qualify evidence. The independently compiled
  profile performs semantic admission.
- Unknown profiles and observation kinds may be retained as rejected custody
  artifacts, but never enter detector evaluation.

## Canonical semantic bytes

NQ canonical JSON is RFC 8785 JSON Canonicalization Scheme (JCS): compact UTF-8,
UTF-16 object-key ordering at every depth, arrays left in order,
ECMAScript-compatible finite-number rendering, exact JCS string escaping, and
no final newline. `sha256:` plus the lowercase SHA-256 of those bytes is the
semantic digest. Canonicalization rejects integers outside the exact I-JSON
range; profiles represent larger counters or identifiers as typed decimal
strings. Raw submitted bytes are hashed separately and are never replaced by
the semantic digest.

String-size limits are UTF-8 byte limits in the authoritative validators. The
schemas retain standard `maxLength` for broad tooling and carry the
`x-nq-max-utf8-bytes` annotation where Unicode code-point length alone is not
sufficient. Deadline decimal strings are constrained to the exact nonzero
`u64` range rather than merely to 20 digits.

## Corpus

`fixtures/manifest.json` identifies positive and hostile cases and the result
plane expected to reject each hostile case. Implementations should consume the
manifest and all listed fixtures. The Python specimen under
`helpers/python-conformance` is intentionally not an SDK; it demonstrates an
independent implementation of the wire contract and the compiled
`nq.conformance` profile.

Release assembly treats v1 as an exact inventory. It refuses additional,
missing, symlinked, or renamed schema/fixture files, strictly decodes the
source manifest, pins the immutable v1 schema byte digests and identities,
recomputes the canonical corpus digest from the exact fixture bytes, and
requires that digest and the fixture counts to match the receipt emitted by
the `nq` binary being packaged.
