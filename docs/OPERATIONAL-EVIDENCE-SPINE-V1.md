# NQ operational-observation qualification v1

FIELD-CLOCK adds `nq.operational-observation-qualification/v1` beside, not in
place of, `nq.diagnostic_execution.v2`.

The profile pins exact Monitor result head
`0569a7dcfdcd500c118fd209d5676bb902d089b3`, exact subject identities,
permitted producer principals, payload schemas, coverage dimensions, bounded
claims, and exact JSON pointers. The intake reopens the signed Monitor body,
its domain-separated Ed25519 signature, subject and producer identities, and
the exact `operational.content.v1` payload bytes. Receiver custody time remains
separate from producer observation time.

Each input independently retains:

- exact raw and Monitor-record digests;
- producer, subject, acquisition outcome, payload schema, and both times;
- claims the exact evidence supports;
- claims for which it cannot testify;
- exact typed refusals.

Contradiction is an additional relation between independently retained claim
values for one exact subject. It does not erase either input or select a
winner. The artifact has no overall disposition, health, success, or authority
field.

Acquisition failure produces cannot-testify entries, never a world claim.
Malformed bytes, wrong signatures, substituted content, subject mismatch, and
producer mismatch remain refusals. Unknown payload schemas remain raw-only.
Producer class is retained as evidence but never participates in claim
precedence, so agent-authored testimony is not privileged.

`TemporalClaimBoundaryV1` freezes exactly the claim IDs NQ supported. A
Nightshift projection may retain a subset while evidence becomes stale or
inapplicable, but validation refuses any added claim. Nightshift owns temporal
lineage, currentness, re-observation, and attention; it cannot widen NQ.
Casework later displays these owner records and gains no authority.

