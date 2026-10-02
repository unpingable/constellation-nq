# PagerDuty condition map for the beta alert registry

This maps each rule anchor of the candidate beta alert registry
(`constellation-beta.rules.yml` and `RUNBOOKS.md` in the Cartography
`architecture/beta-observability/` design, recorded 2026-10-02) to the
`condition.component`, `condition.rule` and `severity` of an
`nq.notification_delivery_intent.v2`. The `rule` values below are the closed
set NQ accepts. The retired `docket-not-ready` anchor is excluded.

**No component evaluates or emits any of these conditions today.** The
registry's rules reference proposed metrics that no component exports yet, and
no rule evaluator (vmalert, Prometheus or Alertmanager) runs anywhere in the
estate. NQ's PagerDuty route only delivers an intent that an operator or a
site script has written and submitted. The "evaluated by" column records that
gap and the issue where each owner was asked for the telemetry.

"Page?" is the registry's `severity: page` label. NQ maps `page` to PagerDuty
`critical` and `warn` to `warning`; a site may choose another mapping, but the
rule and component values are fixed. A warning still creates a PagerDuty alert;
whether it notifies anyone is decided by the PagerDuty service's urgency rules,
not by NQ.

| Rule anchor | component | severity | Page? | Suggested `target_class` | Operator response | Evaluated by (today / future owner) |
|---|---|---|---|---|---|---|
| `nq-no-fresh-acquisition` | `nq` | `critical` | yes | watcher instance class, e.g. `host-posture` | RUNBOOKS.md#nq-no-fresh-acquisition | nobody / NQ metrics (constellation-nq#15) |
| `nq-latency-near-bound` | `nq` | `warning` | no | command class, e.g. `acquire` | RUNBOOKS.md#nq-latency-near-bound | nobody / NQ metrics (constellation-nq#15) |
| `nq-open-cost-growing` | `nq` | `warning` | no | — | RUNBOOKS.md#nq-open-cost-growing | nobody / NQ metrics (constellation-nq#15) |
| `nq-pending-acquisition` | `nq` | `warning` | no | — | RUNBOOKS.md#nq-pending-acquisition | nobody / NQ metrics (constellation-nq#15, #14) |
| `host-posture-unknown` | `host_posture` | `critical` | yes | — | RUNBOOKS.md#host-posture-unknown | nobody / Monitor host-posture (constellation-monitor#14) |
| `host-posture-refusals` | `host_posture` | `warning` | no | refusal stage, e.g. `acquire` | RUNBOOKS.md#host-posture-refusals | nobody / Monitor host-posture (constellation-monitor#14) |
| `host-posture-retention` | `host_posture` | `warning` | no | bound name, e.g. `journal-bytes` | RUNBOOKS.md#host-posture-retention | nobody / Monitor host-posture (constellation-monitor#14) |
| `nightshift-recurrence-missing` | `nightshift` | `critical` | yes | recurrence class | RUNBOOKS.md#nightshift-recurrence-missing | nobody / an external staleness check; Nightshift cannot report its own absence (constellation-nightshift#7) |
| `nightshift-evidence-stale` | `nightshift` | `warning` | no | — | RUNBOOKS.md#nightshift-evidence-stale | nobody / Nightshift (constellation-nightshift#7) |
| `nightshift-cycle-slow` | `nightshift` | `warning` | no | — | RUNBOOKS.md#nightshift-cycle-slow | nobody / Nightshift (constellation-nightshift#7) |
| `docket-unsettled` | `docket` | `critical` (oldest unsettled beyond bound) or `warning` (indeterminate growing) | yes / no | — | RUNBOOKS.md#docket-unsettled | nobody / Docket (constellation-docket#6) |
| `docket-reconciliation-lag` | `docket` | `warning` | no | — | RUNBOOKS.md#docket-reconciliation-lag | nobody / Docket (constellation-docket#6) |
| `ag-executor-unavailable` | `ag` | `critical` | yes | — | RUNBOOKS.md#ag-executor-unavailable | nobody / AG (constellation-ag#14) |
| `ag-repeated-refusals` | `ag` | `warning` | no | bounded refusal reason class | RUNBOOKS.md#ag-repeated-refusals | nobody / AG (constellation-ag#14) |
| `service-down` | `service` | `critical` | yes | unit name, e.g. `nqd.service` | RUNBOOKS.md#service-down | nobody / a host service-state exporter (not yet owned) |
| `host-disk` | `host_posture` | `warning` | no | mount class, e.g. `root` | RUNBOOKS.md#host-disk | nobody / a host filesystem exporter (not yet owned) |
| `build-identity` | `service` | `warning` | no | component name, e.g. `nq` | RUNBOOKS.md#build-identity | nobody / a build-info textfile check (not yet owned) |

Notes:

- The closed component set has no host-level value, so `host-disk` uses
  `host_posture`, the existing host observation owner. Changing that needs a
  new closed value, not a free-form string.
- `docket-unsettled` serves two registry rules with different severities. They
  share a dedup key unless they use different `target_class` values, so a site
  that sends both should give them distinct classes (for example `oldest` and
  `indeterminate`).
- `site` and `target_class` are bounded by format and length only: 64 and 48
  characters of `[a-z0-9._-]`. Keeping their cardinality low is the caller's
  job. NQ refuses only obvious per-event values: anything containing
  `sha256`, a UUID, a `YYYY-MM-DD` date, 32 or more hexadecimal characters, 8
  or more consecutive digits, or only digits. Instance ids such as `host-1`,
  `run-a7` or `i-0abc12` and counts such as `n42` pass, and each distinct value
  opens its own PagerDuty alert.
- The filter also has false positives. A site label with 8 or more digits,
  such as `linode12345678`, is refused. Templated unit names such as
  `getty@tty1.service` cannot be a `target_class`, because `@` is outside the
  character set.
- A resolve matches only the exact dedup key. If the trigger had a
  `target_class`, a resolve without it (or with a different one) is still
  `accepted` by PagerDuty and resolves nothing.
- Runbook anchors refer to the Cartography design's `docs/RUNBOOKS.md`. A site
  can put its own published copy in `runbook_url`.
