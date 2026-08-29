# CALIPER C3 observability handoff

Status: `OBSERVABILITY-HANDOFF-READY`

This artifact describes what was deployed and where it may be observed. It
does not establish monitor health, NQ disposition, deployment qualification,
authorization, or semantic correctness.

## Identity

- environment: `CALIPER/passive-vm-release-reproducibility-and-lifecycle-v1/c3`
- VM identity: `caliper-c3-vm-20260829`
- OS canonical hostname: `caliper-c3-vm`
- OS-reported hostname during qualification: `caliper-c3-vm`
- `expected_reported_host`: `caliper-c3-vm`
- identity comparison: exact string equality
- control endpoint: controller loopback `127.0.0.1:22991`
- guest interface/address: dynamically supplied by QEMU user networking;
  intentionally not claimed as stable deployment identity
- stable DNS: none
- execution profile: one Ubuntu 24.04.4 KVM VM, Linux 6.8.0-138-generic,
  two vCPUs, 2 GiB RAM, one fresh 20-GiB qcow2 overlay

## Access

- monitor-reachable route: controller-local SSH forwarding only,
  `127.0.0.1:22991`
- route class: private loopback, unavailable from LAN or public networks
- application health/readiness URL: none declared
- Prometheus/exporter URL: none installed or declared
- network boundary: QEMU user network uses `restrict=on`; no monitor-specific
  agent, credential, or external route was added
- credentials/tokens: intentionally absent from this artifact

## Host/runtime

Package lifecycle units after inert installation:

- `nqd.service`
- `nq-passive-load-observer.service`
- `nq-recurring-office.service`
- `nq-recurring-office.timer`

The intended bounded lifecycle specified one campaign-specific static oneshot
unit, but the pre-authority refusal occurred before that unit was written:

- planned, absent: `nq-passive-vm-release-reproducibility-and-lifecycle-v1-c3-recurrence.service`

Operational storage targets:

- `/var/lib/passive-vm-release-reproducibility-and-lifecycle-v1-c3`
- `/var/lib/nq-passive-load/samples/passive-vm-release-reproducibility-and-lifecycle-v1-c3`
- `/var/tmp/passive-vm-release-reproducibility-and-lifecycle-v1-c3-results`

The host-side campaign custody root is
`/data/git/caliper-campaign-state/c3-vm`. The VM overlay, serial log, SSH host
key binding, and collected evidence are target custody; the private SSH key is
not monitor input and is not described by content.

There is no HTTP application health surface. Runtime state is exposed by the
declared systemd units, exact NQ JSON status commands, and immutable result
files. PID identity is observational only and is not the deployment contract.

## Expected state

During the bounded lifecycle:

- the planned campaign-specific recurrence service was never materialized;
- packaged timer and services remain disabled unless explicitly invoked by the
  qualified lifecycle;
- one dedicated G1 sample store exists with exact observer/reader ownership;
  inherited mode `02750` is the recorded contract mismatch;
- no recurring timer is enabled;
- after closeout, no activation/grant/enrollment authority exists, the planned
  campaign service is absent, all packaged services are inactive, all timers
  are disabled/inert, the live signing-key path is absent, and the disposable
  VM is powered off. The controller-loopback route is currently unreachable.

Intentionally not asserted:

- systemd `active` means semantic correctness;
- an SSH connection means deployment qualification;
- a file or service exists because an NQ occurrence was authorized;
- OS health means the authority lifecycle qualified.

No Kubernetes resources or Kubernetes RBAC apply to this local-VM target.
