# Passive host-load sampling V1

This contract preserves the exact existing `nq.host.load_pressure/v1`
proposition while replacing only its provider boundary.

```text
load_1m = first finite, non-negative /proc/loadavg token
capacity = Rust std::thread::available_parallelism()
normalized_load = load_1m / capacity
pressure present iff normalized_load >= 2.000
```

The threshold is inclusive. This profile does not substitute CPU utilization,
PSI, provider CPU percent, process liveness, hostname, or another health
surrogate.

> Diagnostic acquisition may consume an observation. It need not cause the
> observation to occur.

## Why the one-shot boundary is not recurrently composable

The historical `nq-host-helper` process reads the same exact inputs, but every
diagnostic acquisition starts a new local process. Linux load average includes
runnable and uninterruptible tasks. Process creation, loader/runtime work, and
the helper itself can therefore perturb the scheduler quantity being measured,
including across the inclusive `2.000` boundary. Distinct pipes, request IDs,
and artifacts solve occurrence attribution; they do not solve this observer
effect.

A passive sampler does not claim zero observer effect. It is a small stable
part of the deployed host. What changes is causal coupling: its fixed bounded
sampling work exists independently of NQ acquisition occurrences, and
retrieving a historical immutable sample cannot alter that sample.

> A stable observer can reduce occurrence-triggered perturbation. It does not
> make observation physically free.

## One closed provider boundary

The `nq-passive-load-helper` binary has two production roles selected by fixed
argv and separately qualified configuration:

* `observe CONFIG` is a long-lived finite sampler. It directly reads only the
  bounded `/proc/loadavg` source and `available_parallelism()`, signs the raw
  facts, and appends one immutable file per occurrence.
* `serve-stdio CONFIG` is the admitted NQ provider. It reads and verifies the
  finite sample store and emits one ordinary `nq.host/v1` report. This path
  never reads procfs, calls `available_parallelism()`, starts the observer, or
  computes pressure.

The sampler and provider share implementation bytes but not authority. The
sampler cannot admit a watcher, mint an NQ recurrence slot/acquisition, run an
NQ evaluator, produce Nightshift support, or decide currentness. The provider
cannot sample the host or fall back to `nq-host-helper`.

The provider-boundary identity binds, through watcher configuration, admission,
request echo, and embedded signed sample:

* exact sampler executable and configuration digests;
* sampler profile `nq.host_load_passive_sampler.v1`;
* sample producer issuer, key ID, public-key digest, and signature;
* subject, scope, and local vantage;
* capacity-context identity;
* maximum sample age;
* exact provider executable/argv/execution identity;
* ordinary V3 origin and provider-intake custody.

Any drift requires a new admission. The sample signature authenticates the
software-held producer key and immutable payload; it does not prove physical
hardware identity. Linode V3 remains the separate logical-instance origin
proof.

Adding this carrier rotates NQ's conservative evaluator source-closure digest
even though the frozen `nq.host` descriptor and load-pressure detector
descriptor remain unchanged. Historical runs are reopened against the exact
source digest and helper-protocol version retained in their own authenticated
admission context. They are not reinterpreted under the newly compiled source
closure. Conversely, a new provider invocation still requires a newly admitted
watcher whose evaluator artifact and current source closure match exactly.
This keeps old custody readable without allowing semantic drift to authorize
new work.

NQ's verified launcher passes fixed argument files to the child as sealed
numeric `/proc/self/fd/N` snapshots. The passive helper accepts that exact
inherited-descriptor spelling after opening and `fstat`-checking a bounded
regular file. Ordinary symlink configuration paths remain refused. This keeps
the retrieval process compatible with sealed launch without falling back to a
mutable deployment path after verification.

## Sampling cadence and acquisition cadence

Sampling cadence belongs to deployment-owned observer configuration. V1 is a
fixed millisecond interval between 100 ms and one hour, a finite maximum sample
count, a hard store-byte ceiling, and optional exclusive expiration. The
long-lived process samples immediately on explicit start and then at its fixed
cadence. It does not backfill missed samples after delay or restart. Restart
creates a new observer-run occurrence; gaps remain gaps.

Diagnostic acquisition cadence remains the finite NQ recurrence enrollment.
An observer sample creates no watcher admission, recurrence slot, acquisition,
provider result, diagnostic truth, Nightshift cycle, or support occurrence.
An NQ recurrence tick does not cause a kernel read.

## Immutable sample

`nq.signed_passive_host_load_sample.v1` contains a signed
`nq.passive_host_load_sample_payload.v1` with:

* sample occurrence and monotonically increasing store sequence;
* exact subject/scope/vantage binding;
* actual wall-clock `observed_at`;
* observer-run, profile, executable, and config identities;
* raw `/proc/loadavg` first token;
* exact `available_parallelism()` result;
* source basis
  `linux_proc_loadavg_plus_rust_available_parallelism_v1`;
* capacity-context identity;
* producer issuer/key and payload digest/signature.

The sample stores raw facts, not `pressure_present`. NQ's existing evaluator
parses the admitted values, divides by capacity, and applies the unchanged
inclusive threshold. Detector sufficiency follows that exact dependency
frontier: a report may remain `partial` because hostname and uptime are
intentionally unavailable while complete `load` coverage is sufficient for
`nq.host.load_pressure/v1`. Partial or unavailable `load` coverage still
refuses; unrelated missing fields do not silently become load-pressure inputs.

The file name contains the immutable sequence and payload digest. Creation uses
`O_EXCL`, exact canonical bytes, file synchronization, and directory
synchronization. Duplicate sequence or occurrence IDs, malformed signatures,
unexpected files, corruption, and sequence rollback refuse the whole provider
selection. One nonblocking store lock serializes the observer generation;
duplicate sampler starts refuse instead of racing sequence allocation. The
long-lived observer loads and verifies its fixed executable, key, configuration,
and prior generation once, rather than rescanning history or hashing its binary
at every cadence. There is no mutable `latest` authority record.

## Temporal selection law

NQ fixes an exact wall-clock cutoff before launching the retrieval provider.
The provider selects the newest sample satisfying both:

```text
sample.observed_at <= request.passive_host_load_sample.cutoff_at
cutoff_at - sample.observed_at <= max_age
```

NQ independently verifies the same relation after profile validation, verifies
that the cutoff preceded provider launch, and verifies the signature and all
deployment bindings again. The maximum age cannot exceed the existing
`nq.host/v1` 300-second reliance horizon.

This is a closed passive-source exception to the ordinary helper timing law.
Ordinary helpers still require all source observations inside their NQ-owned
execution interval. A report with passive custody but no passive watcher policy
refuses. A passive watcher with no exact signed sample also refuses.

A post-trigger sample was deliberately rejected for V1. Even if a trigger
process exits before the sample, its work can remain represented in the
one-minute average. Pre-existing selection is the only qualified law that
removes occurrence-triggered measurement work from the chosen value.

`observed_at` is the sampling time. It is never retrieval time, recurrence-slot
time, file mtime, observer start time, or report receipt time.

## Capacity and vantage

The observer calls Rust `available_parallelism()` directly; it does not replace
it with `/proc/cpuinfo`, online-CPU count, or a provider field. V1 additionally
content-binds the effective Linux inputs that can constrain that result:

* `Cpus_allowed_list` from `/proc/self/status`;
* cgroup-v2 `cpu.max`;
* cgroup-v2 `cpuset.cpus.effective`.

The resulting `nq.available_parallelism_context.v1` digest is pinned in both
observer and provider configuration. Context drift refuses before a new sample
is appended or consumed. V1 intentionally refuses cgroup-v1 hosts because the
closed context proof has not been implemented there.

Deployment qualification must also establish the exact local host/proc
namespace and systemd CPU-affinity/quota properties. The observer unit does not
set `CPUQuota`, `CPUAffinity`, or `AllowedCPUs`; adding one would change the
capacity context and requires requalification.

The service's cgroup placement is part of that exact runtime context even when
no explicit CPU control is requested. In particular, a systemd template
instance normally enters an implicit per-template slice whose inherited
`cpu.max` or cpuset files may differ from a directly qualified service. A
deployment using template instances must pin the already-qualified slice (for
the Linode office, `Slice=system.slice`) or qualify the template slice as a new
capacity context. Process presence, the absence of an explicit quota, and an
equal `available_parallelism()` integer are not substitutes for the exact
content-bound context proof.

## Observer effect and footprint

The long-lived observer performs one bounded file read, one
`available_parallelism()` query, one signature, and one append per sample. It
does not create a process per sample, use a shell, run backend commands, or use
the network. Deployment qualification records CPU time, resident memory,
process/task count, sampling duration, and stored bytes under the selected
cadence.

The observer can itself be runnable while sampling. Its stable independently
scheduled overhead is part of the deployed host whose load is observed. This
contract makes no counterfactual claim about the host with the observer
removed, and it adds no hysteresis or threshold margin.

Retrieval and NQ evaluation occur after the request cutoff, so they cannot
change the exact historical sample selected for their own acquisition. Their
work can still contribute to the host state seen by later samples. That is a
bounded effect on a later world, not a claim of zero disturbance; deployment
qualification must record both sampling and retrieval footprint and keep both
cadences bounded.

The source semantics relied upon here are documented by the Linux kernel's
[`/proc` filesystem documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
and Rust's
[`available_parallelism()` contract](https://doc.rust-lang.org/std/thread/fn.available_parallelism.html).
Those sources do not qualify this NQ boundary by themselves; the executable,
service, context, custody, and hostile tests remain part of qualification.

## Gaps, missing samples, retention, and replay

No eligible sample causes a typed pre-result refusal. There is no old-helper
fallback and no invented observation. A bounded retry of the same pre-provider
acquisition may later find a real eligible sample; it does not create a second
semantic acquisition.

Observer downtime is represented by absent sequence/times. Restart does not
reconstruct missed samples. V1 retention is deliberately finite and
non-deleting: the observer stops at `max_samples`, expiration, or the hard byte
ceiling. It never deletes history to make room. NQ provider intake copies the
complete signed sample inside exact raw report custody, so replay uses admitted
bytes and never consults the live sampler/store.

Long-term generation archival and deletion are not implemented. A deployment
must use finite observer generations and retain any generation needed for
unconsumed samples. Once a sample is admitted, NQ's exact intake/artifact holds
its replay custody.

## Coordination and A4

A4 belongs permanently to the old one-shot-helper provider boundary and
`linode:labelwatch-host` coordination domain. Retiring its finite enrollment
does not release its epoch-1 fence or classify its diagnostic/provider state.

The passive boundary is materially independent, not a renamed domain: it has a
different executable role, signed pre-existing store, temporal selection law,
sample producer, and no acquisition-triggered measurement. Sampling production
remains single-writer. Multiple NQ acquisitions may read immutable samples
concurrently, subject to ordinary intake/store serialization, because reads
cannot change sample bytes. They remain distinct acquisition occurrences even
when policy permits them to bind the same sample.

A new passive watcher requires exact admission and a new finite recurrence
enrollment. No old enrollment or provider identity transfers. A passive
acquisition cannot reconcile, release, migrate, or reinterpret A4.

## Nonclaims

This boundary does not establish currentness, support evidence, physical-host
identity, workload cause, whole-host health, or Nightshift reliance. It creates
no generic sensor registry, metrics platform, time-series database, alerting,
dashboard, scheduler, mutable latest pointer, or arbitrary telemetry source.

Finite-generation lifecycle, storage, restart, signing-key rotation, and
independent recurrence-renewal doctrine are specified separately in
[`PASSIVE_LOAD_OPERATIONAL_CONTINUITY_V1.md`](PASSIVE_LOAD_OPERATIONAL_CONTINUITY_V1.md).

> If the exact proposition cannot survive the new boundary unchanged,
> recurring acquisition remains unsupported.
