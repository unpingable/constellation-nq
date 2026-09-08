# Operator-beta NQ-ng M1B two-VM qualification harness
**Status:** `RUNS_001_002_003_004_005_REFUSED_NO_EFFECT__RUN_006_REFUSED_AFTER_KNOWN_EFFECT_OWNER_SUCCESS__PROTECTED_STORE_CORRECTION_ACCEPTED_PUBLISHED__FRESH_RUN_READY`
**Accepted protected-store correction:** `7750f3185a7fbf3c90c4fc2c8cf3e001e034dc41`
**Helper correction implementation:** `860452c53d63b6162c18a2e0b4aba4acb736baea`
**Accepted helper correction result:** `c62eb7130c813896903e0156bd0593e22befe4a5`
**Accepted package-layout checkpoint:** `8865dcad23f17a1f26716161554530237e04bb9e`
**Accepted Bookworm package-004 result:** `e644390b4b761388569d9dbee5b374294f40ae17`
**Accepted AG store-audit owner:** `837de287497942c79966aa05c083acee9c312261`
**Accepted AG package qualification:** `db4bad1fba2b5ab512cc58356314228167b2f48e`
**Authority effect:** qualification-only local fixtures; no production, provider, default-branch, or deployment authority.

## Purpose

This bounded harness qualifies the accepted `nq.systemd_unit/v1` and
`nq.http_endpoint/v1` observers on two fresh Debian 12 overlays. It is not a VM
lifecycle service, deployment system, Docket replacement, or postcondition
oracle. The controller and target observations remain independent artifacts.
The harness never infers an AG-to-Docket-to-NQ edge from matching identities or
timestamps.

## Observed bounded runs

`operator-beta-m1b-run-001` and fresh `operator-beta-m1b-run-002` each started
both exact local QEMU guests from accepted inputs, but neither `-nodefaults`
q35 launch exposed its NoCloud image. Run-001 used an implicit `ide-cd`; the
accepted run-002 correction bound that device to `ide.1`, but the explicit IDE
device was still absent from both guests. All four serial logs retained the
base hostname and reported `ssh.service` failure before the producer could
connect. The exact producer interruption records remain distinct under
`/data/git/.campaign-artifacts/nq-ng-operator-beta-m1b-20260908/operator-beta-m1b-v1/run-001`
and `run-002`. Both classify `NO_EFFECT_ATTEMPTED`; every named QEMU process
and producer is exited. No package was installed and no NQ, AG, Docket,
system-bus, or fixture-service operation ran.

The accepted virtio correction used by run-003 kept `-nodefaults` and attached
the sealed NoCloud image as an explicit read-only virtio block drive. This is
the exact attachment shape used by the accepted AG clean-host qualification,
rather than a new controller guess. A direct command-shape qualification case
prevents regression to either
IDE form. Run-003 then reached `packages_fixture_installed`: both guests became
ready, the exact packages were installed, and the disabled fixture unit and
machine identities were retained. The first NQ invocation refused because the
previous package required `GLIBC_2.39`, which Debian 12 does not supply. The
exact terminal record remains under the adjacent `run-003` directory; it says
`REFUSED`, `NO_EFFECT_ATTEMPTED`, and null effect custody. All producer and QEMU
processes exited. No NQ artifact, AG attempt, Docket occurrence, system-bus
effect, or fixture-service start occurred.

The current package correction rebuilds exact accepted helper source `c62eb713...`
twice from one exact campaign-owned vendor snapshot inside the locally retained
immutable `rust:1.94.0-bookworm` image with network access disabled. The checked
wrapper requires the two binary and release-artifact sets to be byte-identical
before retaining a result. The resulting exact campaign-owned package has
SHA-256 `0fd1ce9e1be48b56ba5e526993a94c4682499bb9dbd9304dffd4500c01603636`;
all four packaged binaries execute their build-info probes in that Bookworm
image and require no glibc symbol newer than `GLIBC_2.34`. Exact evidence is in
`BOOKWORM-PACKAGE.md`. Runs 001, 002, 003, 004, and 005 are never retried or relabeled;
any later exercise is a fresh run occurrence after independent acceptance.

Fresh `operator-beta-m1b-run-004` used the independently accepted and
published reproducible Bookworm package. Both guests reached `nq_configured`;
the first target watcher admission then refused because the harness invoked NQ
as an ordinary `nq` login process, which cannot enter the separate
`nq-helper` execution account. The exact runtime diagnostic was
`unsafe or unsupported startup runtime ... Operation not permitted`. The
retained refusal says `NO_EFFECT_ATTEMPTED` with null effect custody; both
guests and the producer exited. Run-004 is not retried or relabeled.

The correction reuses NQ's documented one-shot operator boundary: only
watcher admission and diagnostic execution run through a bounded
`systemd-run --wait --pipe --collect` transient unit as `nq:nq`, with the
same four-capability ceiling and service restrictions as `nqd`. The helper
child still clears all capabilities before execution. Configuration,
initialization, export, revocation, backup, and other capability-free commands
retain their existing direct `nq` invocation.

Fresh run-005 used that accepted and published transient-unit boundary. Watcher
admission succeeded and the helper emitted one exact response, but the response
was a valid failed report with unavailable coverage and
`systemd_unit_reference_failed`. The retained provider response and admitted
report show that `RefUnit` required interactive authorization for the
unprivileged `nq-helper` identity. NQ therefore refused the pre-effect
diagnostic as `missing_or_stale_testimony`; it did not launder the failed
observation into the expected mismatch. Run-005 is terminal `REFUSED` at
`nq_configured`, with `NO_EFFECT_ATTEMPTED` and null effect custody. Its guests
and producer are exited, and it is not resumed or relabeled.

The next correction remains inside the helper's observation boundary:
`ListUnitsByNames` supplies the exact stable unit runtime row and
`ListUnitFilesByPatterns` supplies the exact fragment path and unit-file state.
Both are available to `nq-helper` without unit-management authorization. No
D-Bus policy, privilege, service, scheduling, or effect authority is added.
Systemd v252 may internally instantiate or load unit metadata while answering
`ListUnitsByNames`; this bounded manager-owned measurement side effect is
explicitly accepted for the helper correction. The helper requests no retained
reference or unit job, requires the returned row to be job-free, and does not
interpret metadata loading as start/stop mechanics, enactment, or authority.

The target begins with the exact fixture unit installed, disabled, and
inactive. The controller cannot reach the fixed HTTP response. One fresh
machine-bound AG M1A adapter occurrence starts the unit. NQ-ng then produces a
fresh target-local systemd artifact and a fresh controller-vantage HTTP
artifact. The AG adapter is used only as the already-qualified local effect
owner; the run does not claim AG authorization consumption or a Docket database
occurrence. Those composition edges remain a later main-loop gate.

Fresh `operator-beta-m1b-run-006` used exact accepted harness subject
`f412a1fcc71e9dbe4060afa1b0d7dedd89d75230` and package-004. Both pre-effect
observations were retained, the AG owner returned an exact successful receipt,
and the post-effect systemd and HTTP conditions were each established as
explicitly absent. The run then refused at the first package-continuity check.
Its terminal records preserve `KNOWN_EFFECT_OWNER_SUCCESS`, exact effect
custody, last completed phase `effect_owner_completed`, and the instruction not
to restart the producer. Package continuity, restart reopening, AG store-cut
audit, teardown, and the terminal M1B result were not completed.

A snapshot-only diagnostic of the stopped target overlay established that the
SQLite store remained present under `/var/lib/nq`, whose `0700 nq:nq` boundary
made the unprivileged shell's `test -f` return false. The same permission error
could make unprivileged `test ! -s` treat an untraversable WAL as absent. The
accepted correction runs the package-continuity WAL and database predicates and
both terminal database-absence predicates as the owning identity via `sudo`;
checkpointing, exact before/after hashes, package removal and reinstall, and
every other phase remain unchanged. The diagnostic VM was powered off and did
not alter run-006.

## Inputs and retained identity

The runner requires physical regular non-symlink inputs and exact digests for:

- NQ-ng package bytes rebuilt from accepted helper source `c62eb713...` and
  qualification result `8865dcad...` in the immutable Bookworm build
  environment recorded by `BOOKWORM-PACKAGE.md`, exact candidate SHA-256
  `0fd1ce9e1be48b56ba5e526993a94c4682499bb9dbd9304dffd4500c01603636`;
- accepted AG M1A target adapter package `0.1.0-1+m1a4`, exact qualified SHA-256
  `98a4f31f0b6c13653ae95ce55586dbac6d0826b649cd7612882f3716b80e2279`;
- its exact `/usr/libexec/agent-governor-ng/ag-effectd` executable, SHA-256
  `668bdd26646ef6a5ba5502b64984844b84c1f70024a76eb5236af2b17702d068`;
- Debian 12 genericcloud build `20260903-2590`, exact selected SHA-512
  `490f38e2665bc4c31f1bd4cd66dfab3c7695f652a62862a7034d95f8f05ede4146d6dd55c70cc8b0ac9d9b4f54e18f8860bd5ad5ebfb7a8d5e934f3d12cf3817`;
- the exact versioned Debian `SHA512SUMS` bytes containing that filename and
  digest; and
- exact harness source subject, guest driver digest, fixture occurrence, ports,
  paths, and bounds.

The versioned Debian Cloud directory currently publishes `SHA512SUMS` but no
`SHA512SUMS.sign` or `SHA512SUMS.gpg`. The runner records this as
`UPSTREAM_DETACHED_SIGNATURE_NOT_PUBLISHED`, not as signed-checksum custody.
Unless another authoritative signed relation is established, the canonical
M1B signed-upstream-checksum item remains `NOT_QUALIFIED` even if every local VM
case passes.

## Durable execution and recovery

The runner writes `RECOVERY.json` before QEMU starts and atomically replaces it
at every phase transition. It records exact run ID, host, working directory,
source subject, input digests, guest names, PID files, log/evidence paths,
current phase, last completed phase, immutable plan/dispatch digests,
attempt/marker/work identities, effect outcome, and next lawful action. Each QEMU process
has a distinct campaign name, PID file, serial log, fresh overlay, and NoCloud
seed. The harness is launched through a named user-systemd unit so supervising
agent loss does not terminate it. A fresh supervisor uses the query-only
`inspect-run` command to reopen the producer and exact QEMU PID, command-line
token, and process-start identities recorded in `RECOVERY.json`; it does not
restart the producer merely because the prior supervisor disappeared. If and
only if the retained effect state is outcome-unknown, `reconcile-effect` may
query the same AG attempt after the original producer is absent. It first
recomputes the fixed plan and dispatch from retained subject, scope, machine,
and run identities; the AG outcome must bind that attempt and marker before
custody changes. It performs no mechanics and never resumes the campaign
automatically.

An interrupted or failed run writes a refusal record that separately preserves
known-no-effect, known-effect, or outcome-unknown custody. It preserves the run
and exact guests whenever an effect may have started or succeeded; only a
known-no-effect state permits automatic guest termination. It never converts
missing output into success.

Teardown targets only the two exact PID identities and loopback forwards named
by the run. Overlay deletion is not part of automatic teardown; sealed evidence
and overlays remain until an audited cleanup decision.

## Qualification path

The fixed path is:

1. verify inputs, free space, ports, tools, checksum relation, package metadata,
   and absence of same-name guests;
2. retain exact inputs and create two fresh overlays/seeds/identities;
3. boot controller and target with separate machine IDs, host keys, SSH ports,
   and a private fixture link;
4. install and guest-digest-check the exact NQ package on both guests and the
   exact inert AG adapter package on the target; installation must not admit a watcher or start the
   fixture;
5. install the exact disabled fixture unit/content and retain the initial
   systemd/HTTP absence evidence;
6. admit fresh pre-effect NQ instances and retain their exact artifacts;
7. execute one fresh machine-bound AG adapter attempt and retain the plan,
   Docket-shaped dispatch testimony, owner evidence, and terminal receipt;
8. admit fresh post-effect NQ instances and retain the two exact artifacts;
9. inspect/export those artifacts from new processes, remove/reinstall NQ on
   both guests, and prove store/artifact continuity;
10. restart both guests, preserve historical AG success while separately
    recording the expected disabled-unit current state (`present` systemd mismatch
    and `unresolved` HTTP), and prove query-only reopening performs no helper execution;
11. while no adapter writer is active, take the two exact exclusive owner locks,
    truncate and refuse a nonempty SQLite WAL, copy the bounded AG attempt store,
    and require the accepted package's query-only `audit-store` outcome to equal
    the originally retained terminal outcome byte for byte;
12. stop the fixture, require and retain successful local watcher revocations,
    remove packages and
    campaign-owned guest files, power off only the two named guests, retain host
    process/listener observations, and seal the complete artifact inventory.

A pass marker is written only after exact inventory and digest reopening. Live
Docket association, signed Debian checksum custody, full cross-profile matrix,
Nightshift currentness, effect causation, global reachability, and production
remain independently classified. Negative or indeterminate results are valid
qualification outcomes.

## Static qualification and launch custody

The checked producer is `run_two_vm.py`; its pure-local qualification is
`test_run_two_vm.py`, and `scripts/check-operator-beta-m1b-v1.sh` is the
structural gate. The accepted correction passes 30 qualification cases
covering AG-compatible subject framing, durable recovery custody, exact
diagnostic subject/scope/profile/question/policy/vantage/self-identity binding,
producer-unit identity, runtime bounds, exact diagnostic policy/condition
checks, retained image/checksum/package/fixture/config binding, symlink refusal,
terminal complete-inventory reopen, fixed AG plan/effect/action/unit semantics,
owner outcome and recovery binding, content mutation, missing-evidence refusal,
process inspection, a shared pre-query occurrence verifier, same-work/fresh-run
reconcile refusal, same-attempt reconcile refusal, and coherent package,
config, effect, attempt, reconciliation, owner-outcome, owner-store-content,
and accepted-audit-executable substitutions. A direct producer case checks the
locked WAL-zero stable cut, exact source/copy relation, accepted owner query,
and retained cross-component identity record. A separate launch-envelope case
requires the explicit read-only virtio NoCloud drive under `-nodefaults` and
refuses either IDE form. Another direct envelope case requires the documented
transient-unit permission boundary for every helper-executing NQ command and
refuses a plain login-account substitution.
The gate's injected missing-boundary
control refuses deterministically. These cases do not start a VM, install a
package, use the system bus, or perform an effect. The separately retained
run-003 installed the exact prior package and fixture, then refused at its first
NQ invocation. Run-004 installed the accepted Bookworm package and reached NQ
configuration, then refused at its first helper-executing admission because the
harness omitted the documented transient-unit capabilities. Run-005 proved
that transient-unit boundary, admitted one failed systemd report, and refused
before effect because the accepted helper's `RefUnit` call required
authorization unavailable to `nq-helper`. None of runs 001--005 attempted an
effect.

A live run must use a clean, accepted harness commit and a named user-systemd
unit whose `InvocationID` and `MainPID` match the producer. The intended local
shape is:

```sh
HARNESS_SUBJECT=$(git rev-parse HEAD)
systemd-run --user \
  --unit=constellation-beta-nq-m1b-run-001.service \
  --property=Type=exec \
  --property=RuntimeMaxSec=2h15m \
  --collect \
  --working-directory=/data/git/.worktrees/nq-ng-operator-beta-profile-v1 \
  /usr/bin/python3 qualification/operator-beta-m1b-v1/run_two_vm.py run \
  --image <exact-debian-image> \
  --checksums <exact-versioned-SHA512SUMS> \
  --nq-deb <exact-campaign-owned-nq-package> \
  --ag-deb <exact-accepted-ag-package> \
  --output <new-absolute-physical-run-directory> \
  --run-id operator-beta-m1b-run-001 \
  --harness-subject "$HARNESS_SUBJECT" \
  --producer-unit constellation-beta-nq-m1b-run-001.service
```

The exact package and image paths are supplied only after preflight custody is
established; they are not implicit defaults. A resumed supervisor first runs
`inspect-run` against the exact physical run directory and then consults the
named user unit, serial logs, and host log. If the retained effect outcome is
unknown and the original producer is absent, it may invoke query-only
`reconcile-effect`; it never launches a replacement run from missing terminal
output. `RESULT.json` plus `ARTIFACTS.sha256`, or `REFUSAL.json` plus
`RECOVERY.json`, are the only expected terminal families.

## Still unqualified

The harness candidate is not the M1B result. Run-006 establishes exact pre/post
NQ artifacts and one AG-owned successful effect occurrence, but it does not
establish complete package continuity, restart/reopen, AG store-cut audit,
teardown, or a terminal M1B result. Runs 001--005 remain their separate
pre-effect refusals and run-006 is not resumed or relabeled.
The upstream Debian
cloud checksum relation remains
unsigned at the selected versioned directory and therefore cannot satisfy the
canonical signed-checksum item. Live Docket custody, AG authorization
consumption, cross-profile aggregation, Nightshift currentness, deployment,
and production also remain outside this lane. The Bookworm package-004 bytes
are accepted and published at
`e644390b4b761388569d9dbee5b374294f40ae17`; the helper correction is accepted
and published at `c62eb7130c813896903e0156bd0593e22befe4a5`; and the protected
store correction is accepted and published at
`7750f3185a7fbf3c90c4fc2c8cf3e001e034dc41`. A fresh M1B occurrence may now
start from the resulting clean subject; run-006 remains terminal and must not be
resumed or relabeled.

The accepted AG package supplies the query-only terminal receipt/evidence
reopener. This candidate retains an exact WAL-zero owner store cut under the
owner's two-lock boundary and requires the packaged `audit-store` output to
equal the original terminal outcome. NQ-ng records only the exact owner result,
package/executable identities, store-cut identity, and AG/Docket-shaped join
identities; it does not reinterpret AG receipt/evidence semantics or promote
Docket-shaped testimony into a Docket database occurrence. A fresh complete
M1B occurrence and its resulting owner store cut remain `NOT_RUN` until that
distinct occurrence completes and is independently reviewed.
