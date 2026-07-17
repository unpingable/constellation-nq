# Binary release layout

The release builder creates an archive whose top directory is
`nq-ng-VERSION-linux-ARCH`. Beneath that directory, paths are relative to
`/usr`; extraction into a staging directory is recommended before privileged
installation. `MANIFEST.files` documents the intended layout and modes. The
assembler expands the compiled profile catalog, fixed protocol v1 corpus, and
strict system-contract manifest into an exact allowlist, then refuses every
missing/extra path, symlink, hard link, special file, or incorrect
file/directory mode before creating either artifact. Individual staged files
are capped at 256 MiB and the expanded payload at 1 GiB. The manifest is the
compact review copy of that enforced allowlist.
The archive includes the governing plan, development verification guide,
Porter/NetBox addendum, authority-free system-contract schemas and fixtures,
authoritative protocol compatibility notes, and full Apache License 2.0 text.

Every archive contains `share/nq/MANIFEST.sha256`. Verify it from the archive's
top directory:

```sh
sha256sum --check share/nq/MANIFEST.sha256
```

The release directory also contains `SHA256SUMS` plus one checksum file per
tarball and Debian package. The builder neither downloads dependencies nor
invokes Cargo: it assembles already-built `nq`, `nqd`, and `nq-host-helper`
binaries plus a profile catalog verified against the supplied `nq`. The
assembler checks architecture, executes each binary's strict `--build-info`
probe before reading any NQ configuration, rejects debug/test-isolation
builds, and requires every embedded version to equal the requested package
version. It also requires the descriptor inventory to equal the strict profile
manifest and compiled registry, and matches the exact protocol fixture bytes
to the receipt emitted by the supplied `nq`. It strictly verifies the
system-contract assets and requires their compiled-profile fixture to match the
exact catalog being packaged. Release automation must still supply the three
binaries as one reviewed source-revision cohort; a version string is not a
source identity.
