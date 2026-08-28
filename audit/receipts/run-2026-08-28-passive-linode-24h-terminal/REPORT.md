# Linode passive 24-hour terminal receipt

## Classification

`PASSIVE-LINODE-24H-NOT-QUALIFIED — LAUNCH REFUSED BEFORE FIRST CHILD ISSUANCE`

The one authorized charter declared
`[2026-08-28T20:00:00Z, 2026-08-29T20:00:00Z)` but terminated immediately
after its first post-activation exact-bytes gate refused a non-canonical
succession-relation file. This is a valid fail-closed terminal result, not a
24-hour qualification.

H was active from `2026-08-28T20:00:00.513Z` through its retirement event at
`2026-08-28T20:01:01.034Z`. The initial error handler began closeout at
`20:00:00.530Z`; stopping its own launch unit interrupted that handler. Once
the launch unit was inactive, the same bounded closeout procedure completed
without starting or retrying work. No replacement charter was created.

## Exact terminal accounting

```text
H                               retired
G1/G2/G3/G4                     retired, zero samples each
E1/E2/E3/E4                     revoked, zero occurrences each
H G child issuance              0
H E child issuance              0
H succession-edge issuance     0
admissions                      0
activations                     0
recurrence attempts             0
diagnostic acquisitions         0
skipped recurrence slots        0
canonical samples               0
successor handoffs              0
provider starts/fencing epochs  0 / 0
Nightshift cycles               0
old-helper acquisitions         0
```

H retirement event:
`sha256:13a43b80db38c2e3b2608970867ef4359c05d651f7fdd566be6b1162c56442bb`.

E revocation events:

```text
E1 sha256:493528aefa7608785d6319e03d57b2fe9cb293f64699471a003d9e9d546d4c2e
E2 sha256:9269d6a0369403790324d2839c080be28e0c840ac8ccce992b2d0d46e590b997
E3 sha256:7fc5f6422ff868bd29692b9bb725d9b2c5d5a0d82c0ba81f322a59b3f29ca0dd
E4 sha256:0b72b15c8a358289efb4d3318d18fb6af0042aaaf45fcea5a7a990afb75c82da
```

G retirement events:

```text
G1 sha256:a6da21c93a2cd6456303ef3afbd1420103373ba4bfe5ab67684f35615b7b4aa6
G2 sha256:4ccd92d551b017a2d7c2222cdb3f60c71f706a1f87339b06786b066ce2bd6d63
G3 sha256:6f17ef4a943cb7d01af08ec79890af8d8d9214abd9429d97a3edfdde3b63133c
G4 sha256:532535b9297d664fff534b8ea2e77fdd827d837af441ed0e0d268cd232d5d88b
```

## Final service-manager and custody state

The launch, recurrence, observer-generation, handoff, and closeout timers are
all disabled/inactive; `systemctl list-timers` lists zero matching timers.
Recurrence, observer, handoff, launch, and closeout services are not running.
The launch failed-state latch was cleared without restart. Static unit files
remain as immutable evidence but have no enabled link.

No activation object exists. No admissions file exists. The fresh
coordination domain has no holder, in-flight acquisition, fencing epoch,
outcome-unknown state, or provider-safe start timestamp. H retirement, E
revocation, G retirement, and timer disablement ensure no prepared object can
self-activate.

Campaign-owned retained custody at terminal closeout was 986,469 bytes. Host
free space was 25,611,980,800 bytes, well above the 10 GiB guard. The observed
global free-space change includes unrelated `labelwatch` and Docker activity
and is not attributed to this zero-sample charter.

The unrelated civild/labelwatch/Docker activity, historical charters, and A4
were not changed.

The independent access/deployment/launch receipt is
`../run-2026-08-28-passive-linode-fresh24h-launch/REPORT.md`.
