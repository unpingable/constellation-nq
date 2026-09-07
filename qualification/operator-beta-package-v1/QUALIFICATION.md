# Operator-beta NQ-ng package checkpoint

**Status:** `PACKAGE_CHECKPOINT_READY_FOR_INDEPENDENT_AUDIT`
**Package source subject:** `5c064f06d8bcae2fce9dfdb9598167c2343ff706`
**Package source tree:** `c820ea0fc19b065289d9e966926b2ab7a8374b5f`
**Accepted helper result parent:** `9d8624a2d13cb1562b55a81de6f6cea07fb65dcc`
**Accepted helper implementation:** `386358190e974c532d5237d36231fe7e806d100e`

## Observed change

The existing NQ-ng release assembler now requires, architecture-checks, and
build-info-checks `nq-operator-beta-helper` with `nq`, `nqd`, and
`nq-host-helper`. It installs the exact helper bytes only at
`/usr/lib/nq/helpers/nq-operator-beta-helper`. Package installation neither
admits nor executes the helper.

The checked profile catalog now contains the exact compiled
`nq.systemd_unit/v1` and `nq.http_endpoint/v1` descriptors. The existing catalog
verifier proves both descriptor values and their semantic digests equal the
compiled registry. The release payload verifier and human-readable manifest
include the helper and both descriptors in the same closed inventory.

## Qualification evidence

From exact clean package source subject `5c064f06...`:

- `python3 -m unittest scripts/test_release_verifiers.py`: 21 passed;
- full locked workspace: 438 passed, one intentional maintainer fixture emitter
  ignored;
- all-target/all-feature Clippy with `-D warnings`: passed;
- workspace formatting: passed;
- catalog verification: four exact compiled descriptors;
- reproducible tar SHA-256:
  `270d3ba8584d593a191e31cf0877b3059cad4692cfb476c10277291534673aa3`;
- reproducible Debian package SHA-256:
  `979a4df81f32c5453e79eb15a87cf93c0058ef4d69cc7048eb6a1e67282d3761`;
- embedded manifest SHA-256:
  `9fec25f9baeef6caa5f5b7cd1c6498a5ce5a5b26386fe82d377cdd6469b83a4d`,
  covering 79 payload files;
- reproducibility scratch peak: 271196 KiB of the declared 327680 KiB bound;
- missing helper, wrong-component substitution, concurrent writer, package
  builder failure, and interrupted publication all refused at their declared
  boundaries (`missing=1`, `substituted=1`, `lock=1`, `failure=97`,
  `killed=137`).

The tar and Debian package bytes were assembled only in disposable `/tmp`
directories. Their hashes are reproducibility evidence, not durable artifact
custody or publication evidence. A later VM qualification must rebuild the
accepted source, retain the exact campaign-owned package bytes, and bind their
hash before installation.

## Unqualified dimensions and next gate

No Debian package was installed, removed, or reinstalled. No system bus,
fixture HTTP service, VM, provider-intake store, diagnostic artifact, Docket
association, post-effect observation, service activation, production target,
or classic-NQ record was used. The complete M1B result remains unqualified.

The next lawful transition is independent audit of this exact package source
checkpoint. Only an accepted package checkpoint may enter the already-authorized
isolated Debian 12/two-VM package lifecycle and observation qualification. That
future run must retain exact package, image, overlay, service-subject, store,
diagnostic, association, and teardown evidence; acceptance does not authorize
production deployment or transfer any earlier qualification.
