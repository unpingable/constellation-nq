# Diagnostic and operational ownership correction

Status: ratified architecture correction, 2026-07-27.

This record corrects an ownership inversion introduced by NQ-NG commit
`638a1a8507080d2e3653b826b036bf3746b1ba5d`. It changes no executable
semantics, release, deployment, or operational authority.

## Why a correction was required

The first north-star record assigned NQ the broad recursive disposition and
operator-read role and reduced Nightshift to later campaign coordination. That
was inconsistent with both the original Nightshift architecture and the
operator's clarified product direction.

The correction is not a retraction of recursive NQ. It separates two kinds of
composition that the earlier wording conflated:

1. **bounded diagnostic composition:** an NQ node evaluates direct
   observations and child testimony for one exact profile, subject, scope,
   vantage, and question;
2. **operational composition:** Nightshift relates multiple diagnostic
   executions, profiles, subjects, vantages, and times into a read-only
   operational posture.

## Ratified stack

```text
witnesses and providers
  acquire bounded observations
        ↓
one NQ diagnostic
  exact profile + subject + scope + vantage
  custody + admission + coverage + state applicability
  deterministic disposition or typed refusal
        ↓
Nightshift diagnostic operations
  recurrence + expiry + campaigns + transitions
  multi-diagnostic posture + next diagnostic + notification intent
        ↓
monitoring · alerting · operator portraits · reporting · proposed automation
        ↓
human or AG authorization
        ↓
Docket execution
```

Diagnostics are what monitoring is built on. Monitoring is the continuing
operational view over recurrent diagnostic obligations and results. It is not
the lossy semantic input from which a diagnostic must be reconstructed.

## NQ boundary

NQ runs one scoped and bounded diagnostic. It may:

- select and request the exact evidence required by a compiled profile;
- take custody of direct observations and child NQ testimony;
- verify admission, projection, coverage, freshness at evaluation time, state
  applicability, and profile-local coherence;
- recursively compose child testimony when it answers the same exact
  diagnostic question; and
- emit one attributable disposition or typed refusal.

NQ-to-NQ recursion preserves child subject, vantage, claim surface, evidence
dependencies and availability, state frontier, derivation identity,
contradictions, omissions, and projection limits. A parent cannot reconstruct
an erased distinction or treat repeated lineage as independent corroboration.

NQ does not own recurrent monitoring posture, alert escalation, open-ended
cross-diagnostic synthesis, whole-estate situation assessment, repair
authorization, or the primary operations dashboard.

An NQ disposition remains an exact claim about its diagnostic execution. A
later missed recurrence does not mutate those bytes or make the original
diagnosis false. It changes Nightshift's current operational posture.

## Nightshift boundary

Nightshift supplies time, coordination, and operational composition. It owns:

- declared recurrent diagnostic sweeps and on-demand campaigns;
- purpose, scope selection, expected check-ins, jitter, retry, backoff, and
  escalation to deeper declared diagnostics;
- last completed and currently running sweep state;
- expiry and overdue classification without rewriting the prior disposition;
- diagnostic state-transition detection;
- composition across profiles, subjects, vantages, and time;
- replayable human or agent interpretation that cites deterministic inputs;
- the read-only operational posture and useful next diagnostic; and
- exact notification intent, audience, suppression, and escalation policy.

Nightshift does not create direct observations, rewrite an NQ disposition,
launder missing evidence into health or failure, or authorize an operation.
Agent interpretation is a separately identified, cited, replayable Nightshift
input or output. It cannot fill missing evidence, become an NQ fact, or acquire
authority merely because its prose is plausible.

## Monitoring and alerting

Monitoring is a consumer of recurring diagnostics. Its central question is
which declared diagnostics are currently established, narrowed, incomplete,
overdue, blocked, or otherwise unavailable under their exact contracts.

“Last run was clean” is not equivalent to “is clean.” The Nightshift view must
retain at least:

- diagnostic profile and subject;
- last execution identity and evaluation time;
- recurrence obligation and last satisfied check-in;
- evidence freshness and current state applicability;
- coverage and projection limits; and
- current reliance or overdue posture.

Alerting is notification of an exact diagnostic or operational state
transition. A raw threshold sample or ordinary-looking NQ finding does not by
itself mint page authority.

## Dashboard and presentation boundary

The useful NQ-native view is an instrument panel or disposition explorer. It
answers:

- what evidence was admitted;
- which profile, subject, scope, and vantage ran;
- what the diagnostic established or refused;
- which coverage, state, or projection limits apply; and
- which exact disposition was emitted.

The primary operator dashboard is a Nightshift enterprise console. It presents
the declared diagnostic profile inventory, subjects and vantages, recurrence
and campaign state, last-known results, current applicability, gaps,
transitions, and proposed next diagnostic.

The drill-down is:

```text
Nightshift operator portrait
    -> diagnostic execution
        -> NQ disposition or refusal
            -> admitted evidence
                -> witness/provider raw custody
```

Maude or another frontend may render either contract. Presentation owns no
diagnostic, operational, reliance, notification, or authorization semantics.
A consumer status page is a possible downstream projection, not the canonical
operator portrait.

## Notification delivery

A candidate `nq-notify` facet may receive an exact Nightshift or
operator-authored notification intent and record queued, attempted, delivered,
and failed transport state. It must not infer audience, urgency, suppression,
escalation, or authorization from raw NQ evidence or a severity-looking field.

An independently configured raw-diagnostic feed may exist, but it is a
different product contract from an operational page. The two must not be
silently conflated.

## Architecture lineage checked

The correction was checked against the Nightshift repository at
`608b559c13a1f1da36b855674b6fc7fafebe0185`:

- `99ab926` introduced the evidence-to-Nightshift-to-agent/interferometry
  architecture;
- `140bc951` expanded Nightshift scheduling, diagnosis, and review;
- `64c770f` distinguished NQ reliance from Nightshift read-only posture; and
- `f33b75a` recorded the candidate NQ-to-Nightshift channel split.

The operator then explicitly ratified the current boundary:

- witnesses observe;
- NQ diagnoses, scoped and bounded;
- NQ-to-NQ recursion remains a light diagnostic fabric;
- Nightshift conducts recurrent and cross-diagnostic operations;
- monitoring, alerting, portraits, and reporting consume diagnostics;
- Maude or other frontends own presentation;
- humans or AG own authorization; and
- Docket executes.

## Product acceptance question

The primary product question is not whether the system exposes more telemetry
or a richer query language. It is:

> Something is wrong. What is actually established, what remains unknown, and
> which bounded observation would change the decision?

Host Operational Portrait v1 is therefore a constellation milestone rather
than an NQ-alone feature. Its contents remain candidate until separately
ratified from the Stage-1 deployed capability manifest.
