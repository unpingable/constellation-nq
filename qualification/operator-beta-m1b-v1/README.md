# Operator-beta NQ-ng M1B two-VM qualification harness
**Status:** `PRE_EFFECT_RUNS_001_002_003_REFUSED__BOOKWORM_PACKAGE_CORRECTION_CANDIDATE__INDEPENDENT_REVIEW_REQUIRED`
**Accepted package checkpoint:** `8865dcad23f17a1f26716161554530237e04bb9e`
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

## Observed pre-effect runs

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

The package correction rebuilds the unchanged accepted source `5c064f06...`
inside the locally retained immutable `rust:1.94.0-bookworm` image with network
access disabled. The resulting exact campaign-owned package has SHA-256
`e49089844c2b0eb56226cb8abe7b8313dc24b8c9838eae7283733bbab78b609d`;
all four packaged binaries execute their build-info probes in that Bookworm
image and require no glibc symbol newer than `GLIBC_2.34`. Exact evidence is in
`BOOKWORM-PACKAGE.md`. Runs 001, 002, and 003 are never retried or relabeled;
any later exercise is a fresh run occurrence after independent acceptance.

The target begins with the exact fixture unit installed, disabled, and
inactive. The controller cannot reach the fixed HTTP response. One fresh
machine-bound AG M1A adapter occurrence starts the unit. NQ-ng then produces a
fresh target-local systemd artifact and a fresh controller-vantage HTTP
artifact. The AG adapter is used only as the already-qualified local effect
owner; the run does not claim AG authorization consumption or a Docket database
occurrence. Those composition edges remain a later main-loop gate.

## Inputs and retained identity

The runner requires physical regular non-symlink inputs and exact digests for:

- NQ-ng package bytes rebuilt from accepted package source `5c064f06...` and
  qualification result `8865dcad...` in the immutable Bookworm build
  environment recorded by `BOOKWORM-PACKAGE.md`, exact candidate SHA-256
  `e49089844c2b0eb56226cb8abe7b8313dc24b8c9838eae7283733bbab78b609d`;
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
structural gate. The correction candidate passes 27 qualification cases
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
refuses either IDE form.
The gate's injected missing-boundary
control refuses deterministically. These cases do not start a VM, install a
package, use the system bus, or perform an effect. The separately retained
run-003 installed the exact prior package and fixture, then refused at its first
NQ invocation before producing an NQ artifact or attempting an effect.

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

The harness candidate is not the M1B result. A successful two-VM exercise,
complete package lifecycle, AG effect occurrence, NQ artifacts, restart/reopen,
and teardown are still `NOT_RUN`. Run-003 establishes only installation of the
prior package before its incompatible executable refused. The upstream Debian
cloud checksum relation remains
unsigned at the selected versioned directory and therefore cannot satisfy the
canonical signed-checksum item. Live Docket custody, AG authorization
consumption, cross-profile aggregation, Nightshift currentness, deployment,
and production also remain outside this lane. The Bookworm package bytes are a
candidate until this exact pin and build evidence receive independent review.

The accepted AG package supplies the query-only terminal receipt/evidence
reopener. This candidate retains an exact WAL-zero owner store cut under the
owner's two-lock boundary and requires the packaged `audit-store` output to
equal the original terminal outcome. NQ-ng records only the exact owner result,
package/executable identities, store-cut identity, and AG/Docket-shaped join
identities; it does not reinterpret AG receipt/evidence semantics or promote
Docket-shaped testimony into a Docket database occurrence. The live exercise
and its resulting store cut remain `NOT_RUN` until this integrated candidate is
independently accepted.
