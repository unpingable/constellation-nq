# Ubuntu Noble package hardening harness

This directory is a fail-closed acceptance harness, not evidence that the VM
job has run. It requires an operator-supplied, self-contained Ubuntu 24.04
AMD64 cloud qcow2 and an existing nq-ng AMD64 Debian artifact. Both exact
SHA-256 values are mandatory.

```sh
hardening/run-noble-qemu.sh \
  --image /safe/images/noble-server-cloudimg-amd64.img \
  --image-sha256 IMAGE_SHA256 \
  --deb /safe/artifacts/nq-ng_0.1.0_amd64.deb \
  --deb-sha256 DEB_SHA256 \
  --output /safe/new/nq-hardening-run
```

The output directory must not exist and its filesystem must have at least
12 GiB free. The guest-visible overlay is exactly 8 GiB. A host watchdog also
terminates QEMU if total allocated output-directory scratch exceeds 8 GiB, and
QEMU inherits an 8 GiB per-file limit. The harness retains the exact staged
inputs, overlay, NoCloud seed, serial output, SSH transcript, guest receipts,
and a relative-path digest manifest. Its ephemeral SSH private key is deleted
before evidence sealing.

Host preflight refuses missing tools, hashes, non-regular inputs, external
qcow2 backing files, unsupported architecture, an occupied SSH port, inadequate
space, or a failed `qemu-img check`. `--preflight-only` performs those checks
without staging bytes or starting QEMU. KVM is used only when `/dev/kvm` is
readable and writable; otherwise the recorded mode is TCG. Guest networking is
QEMU user mode with `restrict=on` and a loopback-only SSH forward.

The two-phase guest script requires exact Ubuntu 24.04 and exercises:

- clean install and two empty-state reinstalls;
- explicit configuration/database initialization;
- persistent Unix-carrier test, admission, doctor, and collection with
  provably distinct `nq` and `nq-helper` UIDs and GIDs;
- explicit enable, start, restart, stop, start, and enabled-service reboot,
  with a newly admitted report required after each start, restart, and reboot;
- a stopped-state reinstall that must preserve configuration and database
  bytes;
- active remove, Debian purge, retained state/identities, and exact reinstall;
- helper-byte tampering that `doctor` must diagnose as binary drift;
- independent packaged profile and system-contract byte tampering that must
  make the installed-manifest preflight refuse service startup, followed by
  exact-byte restoration and a successful start; and
- final package, service, layout, journal, and byte-hash receipts.

The top-level `dist/nq-ng_0.1.0_amd64.deb` is the preserved 2026-07-20 mint
candidate. Its package lifecycle ran successfully, but the mint-gate audit in
`docs/HARDENING_PROGRAM.md` found that the historical run's 50-file seal omitted
mandatory `guest-results/RESULT` and that the package fails the release-required
refusal-preservation gate. Do not inherit the historical pass or use those exact
bytes for a new qualification. A future full run requires a rebuilt candidate
that first passes the refusal-preservation preflight.

There is no cross-UID or AF_UNIX skip path. The host accepts the guest result
only when all four mandatory pass markers are present. Package purge intentionally
tests Debian's non-destructive behavior; it is not the separate manual evidence
purge described by nq-ng operations.

Reopen a completed run's complete evidence seal without booting a guest with:

```sh
hardening/run-noble-qemu.sh --check-evidence-seal /absolute/path/to/run
```

The reopening path must be the exact physical absolute directory (no symlink,
symlinked ancestor, trailing slash, or dot-component alias).
Only the top-level post-seal `RESULT`, `seal.log`, and the manifest itself are
outside the canonical inventory. In particular, `guest-results/RESULT` and any
other nested file named `RESULT` are sealed evidence. The verifier requires the
manifest to cover the canonical inventory exactly before checking its hashes.
It also admits the intentionally unsealed write-last top-level `RESULT`
semantically: one unambiguous `result=pass`, one nonempty `completed_at`, and no
top-level `REFUSAL` are required.

Run the local non-VM checks with:

```sh
hardening/test-harness.sh
```

That command checks shell syntax and required static invariants, then supplies
a deliberately missing cloud image and requires a persisted `input-custody`
refusal. It does not boot a guest and must not be cited as VM, package, KVM,
cross-UID, or AF_UNIX execution evidence.
