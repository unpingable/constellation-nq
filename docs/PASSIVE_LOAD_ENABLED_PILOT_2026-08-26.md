# Passive load enabled operational pilot — 2026-08-26

Classification: **ENABLED BOUNDED PASSIVE OPERATIONAL CONTINUITY QUALIFIED IN PRACTICE — LIVE OFFICE DORMANT**

This report records the first service-manager-enabled operating window for the
closed passive `nq.host.load_pressure/v1` boundary. It does not change the
proposition, passive sample contract, recurrence law, Linode V3 origin law,
Nightshift cadence, or the historical A4 fence.

> An enabled timer is not an infinite grant.

> An operator can keep the office continuous only by renewing finite authority
> before it expires.

> Exhaustion is a valid terminal operating state, not a failure to be hidden.

## Charter and quantitative horizon

The committed charter is
`pilot:105d3b28-5181-4883-8d2f-a0804c327a7c`, with canonical file digest
`sha256:745d21d689d52122b2bdccc30a27ddd99b221feaae64013c36dcc27342db24a4`.
It permitted exactly two observer generations, two recurrence enrollments,
and at most four recurrence acquisitions through the exclusive 22:03Z close.

The 28-minute horizon was derived from the deployed limits rather than a human
calendar unit:

- observer generations were limited to 15 minutes and 180 samples;
- recurrence enrollments were limited to 10 minutes and two acquisitions;
- two 14-minute generation segments exercised one real renewal boundary;
- two two-occurrence enrollments exercised recurrence renewal separately;
- 15-second sampling plus the one-second policy jitter bound leaves 14 seconds
  of structural headroom inside the 30-second eligibility horizon;
- five-minute diagnostics are useful for this pilot and are not coupled to the
  sampling interval;
- the maximum 112 planned samples were far below 4 MiB per-generation stores
  and the 10 GiB free-space floor.

The charter was committed before service enablement. One manually clocked G5
commissioning sample was necessary to dry-collect/admit the provider-bound
watcher and materialize E1. It did not start a service or create an NQ
diagnostic occurrence.

## Exact grants

Observer generations:

- G5:
  `sha256:d3e8aa2c540cc8e503a6010686e3ab98ea3591b4738ecd69faf01722f77df034`
  - 21:35Z through exclusive 21:49Z
  - 15-second cadence; maximum 56 samples
  - exact predecessor G4
- G6:
  `sha256:b6e813e4751604f015780d5f653596eccb2aaa636d8ac59e8550f3088582123a`
  - 21:49Z through exclusive 22:03Z
  - 15-second cadence; maximum 56 samples
  - exact predecessor G5

Recurrence enrollments:

- E1:
  `sha256:41cf66b67a24a03c7e21849d727a231d3272e209eafe0c584b34929617657667`
  - G5 watcher; five-minute cadence; maximum two occurrences
- E2:
  `sha256:b7ffd88d1c87f05c5f690ef6bc20e7f290c3132aad860142b6cd3036505c0aa5`
  - G6 watcher; five-minute cadence; maximum two occurrences

G6 was activated while only expired E1 existed and produced samples without
creating E2. E2 was then independently admitted, enrolled, and selected without
creating G6 or any sample. Generation renewal and enrollment renewal remained
separate authority events.

## Live sequence and deployment defects

The timer's first E1 wakeup correctly refused before acquisition because a
root-run watcher admission had created root-only admission custody. Restoring
only the new admission/instance-lock files to the established `nq:nq 0600`
custody exposed a second ordering defect: a new provider-bound watcher requires
genesis before successor recurrence. The active configuration also had to be
restored to `root:nq 0640` after root-run atomic config apply narrowed it to
root-only access.

Those failures occurred before provider invocation. Their immutable occurrence
records were retained; no IDs were reused as another semantic occurrence and
no policy was weakened. Exact G5 and G6 passive genesis acquisitions were then
performed. Timer delivery consumed both pre-provider attempts for E1 slot 0
and E2 slot 0 before genesis ordering was complete, so those occurrences are
historically `pre_provider_exhausted` with no provider intake or artifact.

This is an operational product finding: provider-bound watcher admission,
genesis, enrollment, selector installation, and timer activation must be an
ordered runbook. A timer must remain paused until admission and genesis are
complete. Repeated delivery is correctly bounded but can consume the finite
pre-provider attempt budget.

## Restart gap and recurrence outcomes

The observer was deliberately stopped at 21:43:18Z and restarted after E1's
second due slot. The last pre-gap sample was 21:43:15Z. The next real sample was
21:45:26.744Z. No missed sample was reconstructed and sample identities did not
duplicate.

E1 slot 1 ran at 21:44:12.010Z, when the newest sample was about 57.010 seconds
old. It persisted exact governed refusal artifact
`sha256:1d7d17fe2d78aba220a9f7aaadab0cf7df56a3c831405f177d342171df400451`:
`no sample satisfies cutoff and age`. It created no claim and did not fall back
to the one-shot helper.

E2 slot 1 later completed normally:

- acquisition:
  `recurrence:b5c607dcceeee20233b43a9a1dcd297c2e4ab2f53fe02c989623b257b5f9a6c1`
- epoch: 2
- artifact:
  `sha256:f1d1918a681be7ee9e957acda63b926168c73d1e82dda218787e3adb1cdaaedf`
- conclusion: `explicitly_absent`
- diagnostic start: 21:57:09.032Z
- selected immutable G6 sample: sequence 30 at 21:57:00Z
- sample age: 9.032 seconds
- remaining eligibility margin: 20.968 seconds

Successful genesis margins were also bounded comfortably:

- G5 genesis used sequence 12 at 21:41:00Z at age 11.772 seconds, leaving
  18.228 seconds;
- G6 genesis used sequence 14 at 21:53:00Z at age 6.079 seconds, leaving
  23.921 seconds.

These are exact age-law observations, not currentness or health scores.

## Exhaustion and service-manager behavior

G5 reached exclusive expiry with 36 samples; service-manager restart against
the expired locator produced zero samples and returned inactive. G6 reached
exclusive expiry with 53 samples and behaved identically. E1 and E2 each
terminated with exactly two occurrence records and zero remaining authority.
Timer wakeups after zero remaining authority created no acquisitions.

The observer unit remained a static long-lived process with
`Restart=on-failure`. The recurrence evaluator remained a static one-shot. The
timer was enabled only during the chartered window. At close it was disabled
and inactive; observer, recurrence service, and `nqd` were inactive.

No process restart, service wakeup, predecessor success, or expired grant
created successor authority.

## Storage and references

Final pilot stores:

| Store | Samples | Sample bytes | Total store bytes |
| --- | ---: | ---: | ---: |
| G5 | 36 | 46,175 | 82,925 |
| G6 | 53 | 67,945 | 133,500 |

NQ office custody grew from 20,191,660 to 20,480,318 bytes: 288,658 bytes for
new configuration events, admissions, policies, genesis, recurrence events,
provider intake, artifacts, and provenance. The two generation stores totaled
216,425 bytes. The combined observed pilot increment was therefore about
505 KiB over 28 minutes, conservatively about 1.08 MiB/hour, 26 MiB/day,
182 MiB/week, or 0.79 GiB per 31-day month at the exercised workload.

The exact three successful diagnostic executions selected three immutable
samples: G5 sequence 12, G6 sequence 14, and G6 sequence 30. The other 86
samples were not selected by those diagnostic executions. Admission dry runs
also read passive samples but did not create diagnostic occurrences. No sample
was deleted.

Final free space was 27,681,222,656 bytes, leaving about 16.94 GB above the
10 GiB stop floor. Storage does not require archive custody for a 24-hour or
seven-day bounded horizon at measured rates. Projection is not indefinite
safety; unrelated host growth and coherent backup/restore remain outside this
qualification.

## Key and Nightshift standing

Both generations used the already-qualified K2 software key:

- ID: `passive-load-operational-20260826-g2`
- public digest:
  `sha256:6193222f1949cd2d55eb30410623f6bf7dbe325aa561e3eb50e76026daadd86d`
- private custody: observer-owned, mode `0600`, 32 bytes

No key rotation was performed merely for demonstration. Historical K1/K2
verification standing remains unchanged. K2 remains exportable software
custody, not hardware-bound identity.

Nightshift remained byte-identical with two historical cycles, zero external
observations, and zero steady-state observations. Sampling, genesis,
recurrence, renewal, restart, and closeout created no Nightshift cycle.

## Operational recommendation

Protocol invariants remain non-configurable: exact immutable identities,
finite authority, no resampling on replay, no old-helper fallback, no
cross-clock renewal, no referenced deletion, and terminal exhaustion.

Current deployment safety limits remain 20 seconds maximum sampling interval,
15 minutes/180 samples per observer generation, and 10 minutes/two occurrences
per recurrence enrollment. Those limits were useful for qualification but are
not sane manual production defaults. The pilot required many exact identifiers
and more than ten ordered operator actions per generation/provider transition.

Recommended next operating-profile candidate, not yet qualified:

- sampling: 15 seconds;
- diagnostic acquisition: five minutes;
- observer generation: six hours, maximum 1,440 samples;
- recurrence enrollment: six hours, maximum 72 occurrences;
- explicit renewal preparation: 15 minutes before G expiry and at least two
  acquisition slots before E exhaustion;
- failure-pause threshold: two;
- observer restart: `on-failure`, without semantic restart after exhaustion;
- first production review horizon: 24 hours, comprising at most four G grants
  and four E grants;
- key review/rotation: outside the 24-hour pilot horizon; retain the existing
  generation-bounded key law.

The six-hour candidates fit the existing 4 MiB generation-store selection and
measured storage rate, but they exceed the currently activated policy bounds
and therefore require an explicit safety-policy qualification. A 24-hour review
horizon is chosen because disk comfortably supports it while the pilot did not
qualify host reboot, power loss, coherent backup/restore, or long-duration
process behavior. Seven days is storage-feasible but not yet operationally
earned.

The pilot demonstrates enough renewal toil to justify a next campaign for one
finite higher-level operating grant that may authorize at most N unchanged G
and M unchanged E successors through exclusive time T. Such a grant must not
be recursive or infinite. No such grant was implemented here.

Archive custody is **not yet required** for the recommended 24-hour horizon.
It becomes a prerequisite before a future reviewed horizon approaches the
retain-all/free-space reserve or requires active-store rotation.

## A4 and remaining limits

A4 remains diagnostic-outcome unknown, provider-activity unknown, and fenced
at epoch 1 in `linode:labelwatch-host`; its enrollment remains revoked and A5
was not created. The passive pilot neither touched nor reused that boundary.

Still unqualified: software-key non-exportability, physical-host identity,
zero observer effect, physical power loss/reboot, coherent backup/restore,
indefinite retention, automatic grant renewal, and recurring Nightshift
reasoning.

