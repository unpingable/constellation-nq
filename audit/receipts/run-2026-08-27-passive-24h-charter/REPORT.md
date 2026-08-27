# Reviewed 24-hour passive-load charter closeout

Classification: **REVIEWED 24-HOUR CHARTER FAILED CLOSED AT FIRST SAMPLE — CAPACITY-CONTEXT SERVICE-SLICE DRIFT; OFFICE DORMANT**

Date: 2026-08-27 UTC

Host: `sp00ky.net`

Branch: `campaign/passive-watcher-succession-v1`

Charter source HEAD: `4294773535119070c7e4156fc8a9c016bf30dee8`

## Authorized charter

The one authorized immutable H covered the half-open interval
`[2026-08-27T17:00:00Z, 2026-08-28T17:00:00Z)`. It bound 15-second
sampling, five-minute diagnostic recurrence, four contiguous six-hour G
children of at most 1,440 samples, four contiguous six-hour E children of at
most 72 occurrences, three exact directed watcher-succession edges, aggregate
ceilings of 5,760 samples and 288 acquisitions, retain-all custody, and the
10 GiB required-free-space guard.

H was `sha256:deb832fdc11d3b32a56643aa3831570154bfd430c1b8328518f26917824c881f`.
All four ordinary G children, four ordinary E children, and three succession
relations were pre-issued. H exhausted those issuance ceilings exactly; no
handoff was staged.

## Fail-closed result

Before Armed, the mechanically enabled recurrence timer remained semantically
inert. The final journal query retained 18 explicit
`no_canonically_armed_activation` wakeups. The charter database contains zero
recurrence acquisitions, recurrence acquisition events, recurrence slot
events, provider admissions/intakes, evaluation runs, diagnostic artifact
commitments, and diagnostic artifact payloads. All four E children were later
revoked with zero occurrences and all 72 occurrences still unused.

At `2026-08-27T17:01:35.293Z`, G1 attempted its first real sampling slot and
persisted exact event
`sha256:272a6deead6605bb02db70deff9e78a614e1b28c9498ddd998430c64384ff45a`:
`capacity_context_drift`. No sample was committed.

The deployment preflight had qualified the observer in the direct
`system.slice` cgroup context:

```text
capacity context: sha256:6c6e34b0e088655fce62d4dd15ea355e6d79015736c6e0fb5b8219feac492c7d
cpu.max: max 100000
Cpus_allowed_list: 0-3
cpuset.cpus.effective: 0-3
```

The systemd template instance was instead automatically placed in a nested
per-template slice. That cgroup did not expose the pinned `cpu.max` and cpuset
facts, and therefore projected a different exact capacity context
`sha256:4290d9...db94`. The observer correctly refused rather than claiming
vantage equivalence.

The service artifact now pins `Slice=system.slice`. An isolated, non-sampling
service-principal probe of that installed unit reproduced the original exact
capacity-context ID. This is the narrow mechanically determined repair; it
selects no CPU quota or affinity. The installed corrected unit SHA-256 is
`b2910ba65771c43d5294c03a332320c067a9391d147197642dac097684105ec7`.

G1's capacity drift is terminal under the immutable generation law. All four G
and E child ceilings were already spent, so neither G1 nor H could honestly be
rewritten or reused. The run was closed rather than routed around the refusal.

Two earlier bounded defects were repaired without spending diagnostic
authority. First, duplicate `grant-create` delivery had allowed `created_at` to
leak into a second H identity; release `87a6ca3` now converges the same operator
occurrence and intent and refuses conflicting reuse. Second, the first H
activation attempt refused relation files containing a non-canonical trailing
newline before issuing any child. The exact same relation records were
canonicalized byte-for-byte and the idempotent H activation resumed. The
checked-in relation inputs now match those canonical bytes. Neither repair
changed watcher semantics or created an acquisition.

## Exact authority and custody standing

* H: retired by event
  `sha256:665fbfb6a1f0d3bf18048bc93a8c72eea2887847e0ae088a0682b0eec715fbe4`
* G1: drifted, then retired by event
  `sha256:61f36f91a0c4e897fd78612645169924703adf28334c18ffbc072e4d7562ff94`
* G2/G3/G4: never started, then retired
* E1/E2/E3/E4: revoked, zero occurrences each
* samples: zero in every charter generation
* successor admissions: zero
* diagnostic genesis occurrences: zero (the database's one `genesis_records`
  row is the store-creation record made during preflight)
* handoffs/activations: zero
* Nightshift cycles: zero created

The four sample-generation stores retain only their exact generation/event
metadata and consume 44,256 bytes in total. Final available filesystem space
was 26,692,595,712 bytes, comfortably above the 10 GiB refusal guard. Archive
custody remains unnecessary for this horizon.

## Closeout

The recurrence timer and every observer timer are disabled and inactive. The
recurrence service and all observer services are inactive. H and every G/E
child are terminal. No prepared handoff can self-activate. The corrected unit
is installed but grants no authority.

Installed immutable release custody:

* release: `/opt/nq-ng/passive-handoff-87a6ca3-musl`
* `nq` SHA-256:
  `d43f928af34ef7873ae52499c4118ebf660702e8bce40f337788d1cd6e0081ad`
* observer SHA-256:
  `bc8e36f7a3569a8b430da44040acdd7d3a368e595385db03571a332ce30ec9a1`
* release-manifest SHA-256:
  `b2770c1e8159cf5de669618003466cbd557659a65740ac76208048967a058399`
* signing key: mode `0600`, owned by
  `nq-passive-load-observer:nq-passive-load-observer`; secret bytes were not
  copied into audit custody.

A4 was inspected at close and remains exactly:

```text
diagnostic outcome: unknown
provider activity: unknown
coordination domain: linode:labelwatch-host
coordination: fenced
fencing epoch: 1
acquisition: recurrence:d555a10d2b4f11e7c6d550f43a6fd6d07631573bec5c14b54d09ca6b8e04beea
```

## Human decision boundary

The user authorized exactly one reviewed H. That H was created, spent, and
retired, so this campaign cannot mint a replacement. The next legitimate step
is a new human authorization for one replacement 24-hour charter using the
same semantic profile and the now-pinned `system.slice` service shape. It must
receive fresh absolute times, H/G/E identities, operator occurrence IDs, and
succession/handoff identities. Reusing this H or any child would violate finite
authority and immutable failure history.

The recommended narrow choice is to authorize that like-for-like replacement;
no diagnostic, cadence, admission, provider, capacity, retention, Nightshift,
or A4 semantics need change.
