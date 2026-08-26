# Passive load-sampling deployment supplement

Recorded: 2026-08-26T13:53:59-04:00

Classification: **EXACT LOAD-PRESSURE PASSIVE RECURRING ACQUISITION QUALIFIED — LIVE OFFICE DORMANT**

This supplement appends to the existing Linode observation-office receipts. It
does not rewrite or resolve historical acquisition A4.

## Custody

- repository: `nq-ng`
- branch: `campaign/passive-load-sampling`
- starting commit: `f970ddc74fc8d7b63aafcdc5613f39df03edd1e2`
- qualified source commit: `1bc26596d5562090246e3e70d857ebbffe6c3504`
- release archive SHA-256:
  `72eb1fa561a6ee38d2718a2f9b2cd485f3c96421f2cfed9cac539ff9875970d6`
- installed NQ path: `/opt/nq-ng/passive-load-1bc2659/bin/nq`
- installed NQ SHA-256:
  `bb30ce631f5b1fd50b35ef23c8bfbbe5faf1dfdf54b8c3a8ef0fd7d619d05a46`
- installed passive helper path:
  `/opt/nq-ng/passive-load-69584e3/lib/nq/helpers/nq-passive-load-helper`
- installed passive helper SHA-256:
  `7dceb31830ed6b4930e3089367a59ac80c97f35fd7d2a396c7a08186fe2c38b6`

The helper/configuration and the NQ acquisition remain separately identified.
The helper is a software-key-authenticated passive fact producer and does not
prove physical hardware identity.

## Preserved proposition

The provider-boundary change preserves the exact frozen proposition:

```text
load_1m = first finite non-negative /proc/loadavg one-minute value
capacity = Rust available_parallelism()
normalized_load = load_1m / capacity
pressure present iff normalized_load >= 2.000
```

The observer emits authenticated raw facts. NQ remains the sole owner of the
division and inclusive threshold. CPU utilization, PSI, provider CPU percent,
hostname, and liveness are not substitutes.

## Passive boundary

- watcher: `labelwatch-host-passive`
- governed subject: `host:labelwatch-host`
- profile: `nq.host/v1`
- local vantage and host scope remain exact
- sample schema: `nq.signed_passive_host_load_sample.v1`
- observer profile: `nq.host_load_passive_sampler.v1`
- sample source basis:
  `linux_proc_loadavg_plus_rust_available_parallelism_v1`
- sample store:
  `/var/lib/nq-passive-load/samples-passive-69584e3`
- passive provider configuration SHA-256:
  `9c7d3a7717ebfb6ea374cf879618b8b7a743b2ba46326e9830d6cc66791fec94`
- observer configuration SHA-256:
  `783e3a66683b35939f80759eae604e3f9cd2723836c3fd3b7059df2bace63507`
- observer producer public-key digest:
  `sha256:57459d9c6bd8aaf10e0c60a36f3f48bb861956e5234cf03a8372878698ef81a3`
- capacity-context identity:
  `sha256:6c6e34b0e088655fce62d4dd15ea355e6d79015736c6e0fb5b8219feac492c7d`
- final immutable sample-file count: 22

NQ selects the newest authenticated pre-existing sample whose `observed_at` is
at or before the acquisition cutoff and no more than 30 seconds old. The
acquisition binds that exact sample. It neither starts the observer nor reads
the kernel measurement source. Replay uses retained intake and never resamples.

The bounded live observer had one task, 856,064 bytes `MemoryCurrent`,
79,864,000 ns `CPUUsageNSec`, and 1,256-byte sample files. This establishes a
small stable independently scheduled footprint, not zero observer effect.

## Admission and manual acquisitions

- admission occurrence: `27c4a406-0293-4259-8b4d-551f0ff2d85d`
- admission binding:
  `sha256:1e84cba180ddb2038e57566902255bdc746ddd4496e45dc514c5c3cdec37de07`
- watcher semantic digest:
  `sha256:eca928e1aa6293711b0ad7a4c62acef258aedf183864b0df7d48b2580d29ef8d`

Successful bounded manual passive acquisitions:

- `passive-load-labelwatch-host-20260826-4`
  - run: `c1ffa45d-5ef3-4f5d-bf44-2ab9af5df6ca`
  - artifact:
    `sha256:349c545c7456162e298e75f7d5a70e7d70d544e717b6ecbba56a88e34c354514`
  - condition: `explicitly_absent`
  - exact replay produced no new origin event, run, artifact, or sample
- `passive-load-labelwatch-host-20260826-5`
  - run: `7a2640ce-bd73-4406-86cd-c070695f415d`
  - artifact:
    `sha256:41b8e79582c34db75e5ac8c48491bc205d8f7038386d30663c1594407dad02f3`
  - condition: `explicitly_absent`

Earlier passive attempts `-1`, `-2`, and `-3` remain immutable historical
attempts. Their refusal/incomplete states exposed evaluator-completeness and
historical-reconstruction defects that were repaired without rewriting them.

## Finite recurring-office supplement

- active policy ID:
  `sha256:e08af78ecd343759420fc6f4043bb326c8b2f7d272b627f3989cfbb50068ade7`
- policy activation event:
  `sha256:a9006321e2b1adb349a7a5eab313368a1567604c7559bc1929c7a7c5db59842c`
- enrollment ID:
  `sha256:e5a299aa3c6c5a5077dc3be951031f2aec5039aef48abe84d56b1fa3b259e122`
- coordination domain:
  `passive-load-samples:sha256:9c7d3a7717ebfb6ea374cf879618b8b7a743b2ba46326e9830d6cc66791fec94`
- finite occurrence bound: 2
- enrollment state at close: `exhausted`
- remaining occurrences: 0
- failure streak: 0

Occurrence 1:

- slot index: 2
- slot/acquisition identity:
  `sha256:21a11b4b43a90accee4cc70cb8d4b06c3c02004bcc7dc45f360c3fa953ba0747`
- fencing epoch: 1
- run: `e54c5101-bc03-4157-b156-6a415546f50b`
- artifact:
  `sha256:b2ad01fd679cceac65dc68c3b96595fcb089466f85f1a6104cec56f9bd522c25`
- condition: `explicitly_absent`
- duplicate same-slot tick: no-op; zero additional origin/sample/provider work

Occurrence 2:

- slot index: 3
- slot/acquisition identity:
  `sha256:4312a44435a58a8e0f3b38b4553110233cc9eb7a03634e35111c46459c314094`
- fencing epoch: 2
- run: `805d49d5-f1f3-4340-ad74-d78843001530`
- artifact:
  `sha256:5864098009de762dcc0e9be1f9aeb2e664ffcf0211350c5a655ecc7fd273880f`
- condition: `explicitly_absent`
- executed through the installed systemd one-shot boundary

Both recurrence acquisitions replayed exactly. A subsequent service invocation
returned `enrollment_unavailable` / `exhausted` and caused no origin proof,
sample, or acquisition. No Nightshift cycle was created.

## A4 remains untouched

- old enrollment:
  `sha256:37878cc8a3e2342be8e3dfbc6b3d93ad0fe7a3d9574a3f1237dd83a52c53935c`
- A4:
  `recurrence:d555a10d2b4f11e7c6d550f43a6fd6d07631573bec5c14b54d09ca6b8e04beea`
- old domain: `linode:labelwatch-host`
- fencing epoch: 1
- diagnostic outcome: unknown
- provider activity: unknown
- coordination: fenced
- old enrollment: revoked
- A5: not created

The new passive boundary is materially distinct because it consumes signed
immutable pre-existing samples and cannot execute the old measurement helper.
It does not rename, reconcile, release, migrate, or reinterpret A4.

## Installed deployment identities

- recurrence unit SHA-256:
  `0f129e754208e02e5641f760d87534484390ec316899610587dbaa1e35f8f39b`
- policy file SHA-256:
  `8f09f62fe07aebea33bcb94650515d6158dbe86cf97f836ceba46ddbbab8232e`
- enrollment file SHA-256:
  `ca2555332eb692863d13dddd487a3a17fb10a4d174eab007e62ef2e19cb0bb1d`
- environment file SHA-256:
  `99baebc801e20c984c89b26b09754230daa7e1aef5e1efd98296c435e74619f9`
- final NQ database SHA-256:
  `02c66db96f9a278a1b9479b7e83169f89b4f2442cd91f58a94f2f62eee7399e2`
- final recurrence-status export SHA-256:
  `9a41c40a26efc0d1ccb3b70976432377e1ccbde31a2d068024a0da7e76f15fa8`

At close:

- `nq-passive-load-observer.service`: inactive
- `nq-passive-recurring-office.service`: inactive
- `nq-passive-recurring-office.timer`: disabled and inactive
- no uncontrolled observer, acquisition timer, or Nightshift cadence was left
  running

## Validation standing

- final release checksums, manifest, catalog, protocol/system-contract, and
  payload verifiers: passed
- NQ locked workspace/all-target suite: all relevant targets passed; one
  aggregate run saw a single environmental timeout in the same-inode script
  mutation test under high load
- full serial `nq-core` rerun: 198 passed, 0 failed, 1 intentionally ignored
- NQ administrative process-boundary target: 8 passed
- all remaining workspace packages and hostile suites: passed
- Clippy (`-D warnings`), formatting, all structural scripts, and
  `git diff --check`: passed
- Nightshift locked workspace/all-target regression: passed
- Nightshift canonical no-actuation gate and injected self-test: passed
- strict-host-key final live verification: hashes, sample count, A4 fence,
  exhausted passive enrollment, and inactive/disabled units all matched this
  receipt

## Remaining limits

The result qualifies exact passive recurring acquisition for this proposition
and deployment boundary. It does not qualify zero observer effect, a physical
host identity, continuous cadence, long-term sample-generation deletion,
automatic Nightshift cycles, or generic telemetry. Continuous operation still
requires a separately reviewed observer/acquisition cadence, finite-generation
renewal and retention/archive policy, failure escalation, and explicit enablement.
