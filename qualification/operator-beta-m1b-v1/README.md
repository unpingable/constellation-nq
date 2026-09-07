# Operator-beta NQ-ng M1B two-VM qualification harness
**Status:** `CORRECTION_CANDIDATE_READY_FOR_INDEPENDENT_REAUDIT__LIVE_RUN_NOT_STARTED`
**Accepted package checkpoint:** `8865dcad23f17a1f26716161554530237e04bb9e`
**Authority effect:** qualification-only local fixtures; no production, provider, default-branch, or deployment authority.

## Purpose

This bounded harness qualifies the accepted `nq.systemd_unit/v1` and
`nq.http_endpoint/v1` observers on two fresh Debian 12 overlays. It is not a VM
lifecycle service, deployment system, Docket replacement, or postcondition
oracle. The controller and target observations remain independent artifacts.
The harness never infers an AG-to-Docket-to-NQ edge from matching identities or
timestamps.

The target begins with the exact fixture unit installed, disabled, and
inactive. The controller cannot reach the fixed HTTP response. One fresh
machine-bound AG M1A adapter occurrence starts the unit. NQ-ng then produces a
fresh target-local systemd artifact and a fresh controller-vantage HTTP
artifact. The AG adapter is used only as the already-qualified local effect
owner; the run does not claim AG authorization consumption or a Docket database
occurrence. Those composition edges remain a later main-loop gate.

## Inputs and retained identity

The runner requires physical regular non-symlink inputs and exact digests for:

- accepted NQ-ng package bytes rebuilt from package source `5c064f06...` and
  qualification result `8865dcad...`;
- accepted AG M1A target adapter package `0.1.0-1+m1a3`, exact qualified SHA-256
  `2852dc8a516980c4a1936d64a3a3f472d95fccf5eb3935f01a1be277f6b24f26`;
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
current phase, last completed phase, and next lawful action. Each QEMU process
has a distinct campaign name, PID file, serial log, fresh overlay, and NoCloud
seed. The harness is launched through a named user-systemd unit so supervising
agent loss does not terminate it. A fresh supervisor uses the query-only `inspect-run` command to reopen the producer and exact QEMU PID, command-line token, and process-start identities recorded in `RECOVERY.json`; it does not restart the producer merely because the prior supervisor disappeared. If and only if the retained effect state is outcome-unknown, `reconcile-effect` may query the same AG attempt after the original producer is absent. It performs no mechanics and never resumes the campaign automatically.

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
11. stop the fixture, require and retain successful local watcher revocations,
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
structural gate. The correction candidate passes 16 qualification cases covering
AG-compatible subject framing, durable recovery custody, exact diagnostic subject/scope/profile/question/policy/vantage/self-identity binding,
producer-unit identity, runtime bounds, exact diagnostic policy/condition
checks, checksum binding, symlink refusal, terminal complete-inventory reopen, AG/NQ cross-binding, content mutation, missing-evidence refusal, process inspection, same-attempt reconcile refusal, and coherent substitutions. The gate's injected missing-boundary
control refuses deterministically. These are harness results only: no VM,
package install, system bus, fixture service, or effect has run.

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

The harness candidate is not the M1B result. The two-VM exercise, package
lifecycle, AG effect occurrence, NQ artifacts, restart/reopen, and teardown are
all still `NOT_RUN`. The upstream Debian cloud checksum relation remains
unsigned at the selected versioned directory and therefore cannot satisfy the
canonical signed-checksum item. Live Docket custody, AG authorization
consumption, cross-profile aggregation, Nightshift currentness, deployment,
and production also remain outside this lane.
