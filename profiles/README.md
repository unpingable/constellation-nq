# Compiled profile catalog

These release assets are snapshots of the profile descriptors compiled into
`nq`. They are publication artifacts, not dynamically loaded configuration.
The compiled Rust registry remains authoritative.

`manifest.json` records the descriptor identity printed by `nq profiles list`.
Each `semantic_digest` is SHA-256 over the RFC 8785 canonical descriptor JSON;
it is intentionally not a digest of the whitespace in the pretty-printed file.
Regenerate a descriptor with:

```console
nq profiles show nq.conformance 1
nq profiles show nq.host 1
```

An installed descriptor must match both the corresponding command output and
the qualified semantic digest before it is packaged. The manifest and every
descriptor use duplicate-key-refusing JSON decoding; manifest fields and
entries are exact, identities and descriptor names are unique, and the
top-level descriptor-file inventory must equal the manifest. An unlisted JSON
file is a release error, not an implicitly discovered profile.

Verify a staged catalog against the exact binary being packaged with:

```console
python3 profiles/verify_catalog.py /path/to/nq
```

## Owner failure vocabularies

`failure-codes.json` publishes each compiled profile's closed
collection-failure vocabulary as opaque tokens, exactly as `nq profiles
failure-codes` prints it. The source of truth is the owning profile module's
enum (`FilesystemFailureCode`, `MemoryFailureCode`); the helper builds every
failure from that type, so a token cannot be emitted that the owner did not
declare, and the tokens' meaning lives only in the owning module. Profiles
whose helpers carry no typed failures list an empty vocabulary. The verifier
refuses a removed or added token, a duplicate, a non-token, a vocabulary for
a profile outside the manifest, and, with `--helper`, a helper binary whose
served vocabularies differ from `nq`'s:

```console
python3 profiles/verify_catalog.py /path/to/nq --helper /path/to/nq-host-resource-helper
```
