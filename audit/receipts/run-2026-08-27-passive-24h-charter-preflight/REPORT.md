# Reviewed 24-hour passive charter preflight

Classification: **NOT ENABLED — V1 SUCCESSOR ADMISSION AND ACTIVATION HANDOFF REQUIRE MID-WINDOW ACTION**

Date: 2026-08-27 UTC  
Host: `sp00ky.net`  
Branch: `campaign/passive-watcher-succession-v1`  
Preflight code HEAD: `a7635f11b5e6e2a10454ca816a23d8c15dd9bfc9`

## Authorized candidate

The reviewed candidate was one exclusive 24-hour H containing four contiguous
six-hour G children, four contiguous six-hour E children, three exact directed
watcher-succession edges, and aggregate ceilings of 5,760 samples and 288
acquisitions. Sampling was 15 seconds, acquisition was five minutes, retention
was `retain_all`, and the existing 10 GiB required-free-space guard remained
mandatory.

## Exact preflight result

The charter was not materialized or activated.

The finite-H ledger can issue all four future G children, all four future E
children, and the three closed succession relations before the first window.
The executable `ordinary_g_and_e_children_consume_finite_h_budgets_append_only`
conformance test proves those exact contiguous 6h/24h boundaries and ceilings.
That is not sufficient for unattended operation.

Every distinct successor watcher still requires a fresh ordinary admission.
`watcher admit-successor` deliberately invokes the ordinary admission dry
exchange. The exact successor provider is bound to its future observer
generation and immutable sample-store generation. Before that future G enters
its half-open active interval and produces a truthful eligible sample, the
provider returns the governed `no exact eligible pre-existing passive load
sample is available` refusal. The missing-sample conformance test proves there
is no old-helper or on-demand sampling fallback.

Activation cannot be armed early as a workaround. Readiness validation requires
the named G to be currently inside its exact interval, the E to be active, the
fresh successor admission to be the current exact binding, genesis intake to be
complete, and the installed provider/store/service custody to match. V1 has no
bounded handoff evaluator that changes observer generations, creates a fresh
admission/genesis, or stages/validates/arms the next activation unattended.
Systemd presence and timer wakeups grant none of those facts.

Consequently the proposed 24-hour run would require mid-window operator work at
each six-hour boundary even if all child issuance records were staged. That
violates the authorization condition that every identity and semantic
prerequisite for genuinely unattended operation exist before enablement. No H,
G, E, succession, admission, activation, sample, or acquisition was created by
this preflight.

## Validation witnesses

The focused finite-H/activation conformance surface passed all eight tests,
including exact four-child issuance, finite exhaustion, non-recursive H, and
timer inertness before Armed. The passive-provider missing-sample/no-fallback
test also passed.

Read-only live inspection showed:

```text
observer service: inactive
recurrence service: inactive
recurrence timer: disabled / inactive
H4: retired and exhausted
final activation: closed / timer inert
new 24-hour H: absent
```

A4 remains exactly:

```text
diagnostic outcome: unknown
provider activity: unknown
coordination domain: linode:labelwatch-host
coordination: fenced
fencing epoch: 1
acquisition: recurrence:d555a10d2b4f11e7c6d550f43a6fd6d07631573bec5c14b54d09ca6b8e04beea
```

## Remaining decision surface

An unattended charter needs a separately qualified, finite, non-recursive
handoff authority that can consume already reviewed H succession standing and
produce the required fresh successor admission/genesis/activation at the exact
generation boundary without relaxing admission or sample eligibility. V1 does
not contain that authority. Pre-admitting against missing/future samples,
reusing one watcher identity, or treating systemd as authority would contradict
the qualified doctrine.
