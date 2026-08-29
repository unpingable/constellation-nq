# GLASSHOPPER passive Linode terminal closeout receipt

## Classification

`CLOSEOUT COMPLETE; CAMPAIGN NOT QUALIFIED / G4 OUTCOME UNKNOWN`

The established closeout timer started at
`2026-08-29T21:45:05.009070Z` and its service finished successfully at
`2026-08-29T21:45:13.923199Z`. The terminal audit was read-only. It did not
trigger, retry, reconcile, backfill, repair, or infer any occurrence.

Qualification is refused because G4 acquisition
`recurrence:b8a1cf7c04f6b921119d5609a4c906b38d6174a5776222b2c4de406250c9f095`
claimed fencing epoch 210, began provider attempt 1, and reached the 90-second
timeout without a replayable exact result. The durable acquisition event is
`sha256:c07ac56461a2eb96907f0199c6d7d5cca12ce5b48eb2dd75749a63fe984204a7`
(`outcome_unknown`). The durable coordination event is
`sha256:4acd97a10439b6dfba51309a49dceea0db9970a2669530be7be9abb8a4b4fe20`
(`fenced_outcome_unknown`). Inspection reports the occurrence unknown and
fenced, retained provider evidence `available_not_applied`, and reconciliation
`null`. No second attempt or reconciliation event exists.

## Exact terminal accounting

```text
recurrence acquisitions created     213
provider invocation starts          210
provider succeeded                  209
provider outcome unknown              1
coordination claims                 210
coordination releases               209
coordination fenced unknown           1
provider reconciliation events        0
provider attempt number > 1           0
duplicate acquisition slots           0
acquisition without created event      0
latest_only skipped slots              6
samples retained by G1/G2/G3/G4     1440 / 1440 / 1440 / 1440
```

The six `latest_only` skip records are retained as skips. There was no catch-up
burst. G1 slot 71 remains acquisition
`recurrence:d562a282d7ba8d1a6ddd29bd4d61e196d5cda6ca5a4394f79e1e84261fd4507e`:
one `created` event, attempt 0, no fencing epoch, and zero coordination events.
No terminal outcome is inferred for that slot.

## Closed state and custody

The launch, recurrence, G2/G3/G4 observer, three handoff, and closeout timers
are disabled and inactive. The G1 observer timer is absent by design.
`systemctl list-timers` reports zero campaign timers. Launch, observer,
handoff, and closeout services are inactive; the closeout service result is
success. The recurrence service retains its exit-code/failed latch from the G4
unknown-outcome path, but no campaign process or listener remains. Static unit
files remain retained evidence and cannot schedule work.

The four office activations are closed, the four enrollments are revoked, the
grant refuses future child issuance, and the four generations are retired.
SQLite `PRAGMA integrity_check` returned `ok`. Ledger controls found zero
duplicate acquisition slots, zero acquisitions without a created event, zero
attempt numbers above one, and zero reconciliation events.

The retained static-mechanics manifest has digest
`sha256:aba7b9ef6610fe9101b58f56e211fd021456855cef05beb6519a0806576943d6`;
all 14 listed remote files verified. The retained local configuration manifest
has digest
`sha256:7b74d86cd956beb61a502aa6537b040193906f169eee3ecace4231af2a0e4e1d`.
The exact installed release identities remained:

```text
nq                      sha256:d12ee481cec6d149d634f7b3a349398eb4d271a767d9b6178636b60ef9d33d69
nqd                     sha256:3a922f61a6fd7c9310b264d40d431f2f53d984b29e22966351b37bbe6a2a40af
nq-host-helper          sha256:cd12ed5620a34fae531cbb5d451fd5b3519395ce2f3402a12d3fd4e7d3a87494
nq-linode-origin-helper sha256:ff5c3ab94e423484cc2698623cf1efb81f3394dc2df7d3f1ce479b30c0e193e6
nq-passive-load-helper  sha256:a966ad1a36a8c61a75fe866a115a3531446ca2bbf3a7795e8af406af4182fc08
```

Observed provider reports continued to identify the machine as `localhost`,
while the authorized subject remained `host:labelwatch-host`. This mismatch is
preserved as a qualification limitation; it was not repaired or normalized.
The previously recorded zero-attempt staging wake limitation is also
unchanged.

## Audit provenance and repository custody

The independent terminal collection contained 19 files in a mode-0700
temporary directory. Its 18-entry `SHA256SUMS` verified, and that manifest has
digest
`sha256:ea4237e1da04b08fcbd9b69cbc5af39c9f9d121fa16e0761b9620356ebf02af2`.
The raw 78 MiB collection was a temporary audit fixture and is not committed;
this compact receipt retains its decisive identities and counts.

At audit admission, the local branch, existing remote campaign ref, and live
audited source were exact commit
`460d97c01fedb507ffad090c46437a8d833f93e7`. The closeout adds only this
campaign-owned record. It grants no authority, performs no activation, and
does not convert the unknown G4 outcome into success or failure.

The launch receipt and immutable launch inputs remain in
`../run-2026-08-28-passive-linode-glasshopper-launch/`.
