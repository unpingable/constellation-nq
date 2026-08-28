# GLASSHOPPER observability handoff

This is a bounded descriptive handoff for the live charter
`gh24-20260828-f249176c`. It is not a qualification receipt, does not alter
the launch classification, and does not grant authority. Facts were observed
read-only at `2026-08-28T22:15:29.955Z` through
`2026-08-28T22:15:53.427Z`. No credential is recorded.

## Target and reported-host discrepancy

The control route is `labelwatch.neutral.zone`, resolving exactly to
`192.46.223.21`. The host runs Ubuntu 22.04.5 LTS on x86-64.

The campaign's `expected_reported_host`, derived from its explicit logical
subject and watcher identity, is `labelwatch-host`. The operating system
reports `localhost` through `hostname`, `hostname -f`,
`hostnamectl --static`, and `/etc/hostname`. Prometheus node exporter
reports `nodename=\"localhost\"`. Therefore:

```text
OS reported hostname       localhost
exporter reported nodename localhost
expected_reported_host     labelwatch-host
OS == exporter             true
OS == expected             false
exporter == expected       false
```

The passive sample format exports no hostname; the inspected immutable sample
had sequence 127 and `hostname = null`/absent by schema. This is not treated as
a substitution for the expected value. The discrepancy is descriptive: NQ's
subject is the explicit logical identifier `host:labelwatch-host`, while
substrate origin is bound by the qualified instance-metadata identity. Hostname
similarity is not authority or continuity evidence.

## Routes, listeners, and status surfaces

* `labelwatch.neutral.zone:22` was reachable from the control host over
  authenticated SSH. The host listener is bound on IPv4 and IPv6 wildcard
  addresses. This is the authorized management path, not an NQ data exporter.
* Prometheus node exporter listens on wildcard port `9100/tcp`. A bounded
  loopback read of `/metrics` returned the node identity above. It exposes
  generic OS metrics and does not report GLASSHOPPER semantic authority.
  External reachability was not tested; a wildcard bind alone is not a
  firewall/reachability claim.
* The pre-existing `/opt/notquery/nq-monitor` listener is bound on wildcard
  `9848/tcp`; a loopback read of `/` returned HTTP 200. The
  pre-existing `nq-witness` listener is loopback-only on `9847/tcp`;
  `/state` returned HTTP 200. No binding from either service to this
  charter's state or receipts was established, so neither is a canonical
  GLASSHOPPER status surface.
* A pre-existing receipts-feed listener is bound on wildcard `8100/tcp`;
  a loopback read of `/` returned HTTP 200. It is unrelated to the
  charter and is recorded only to prevent mistaken attribution.
* The GLASSHOPPER charter itself has no observed TCP or UDP listener. Its
  watchers use the local `stdio` carrier. The configuration names
  `/run/nq-gh24-f249176c/nqd.sock`, but no socket existed at observation
  time because no campaign daemon is running.
* Canonical live status is read through the authenticated control path from
  systemd state/journal, immutable sample files, the append-only SQLite
  ledgers, and the campaign receipt directory. These are permission-bounded
  local surfaces, not anonymous network endpoints.

The observed default IPv4 route used `eth0` via `192.46.223.1` with
source `192.46.223.21`. Docker bridge routes `172.17.0.0/16` and
`172.18.0.0/16` were also present. No network namespace, firewall, or
external-route equivalence is inferred from this route listing.

## Units, storage, and expected live state

The exact charter interval is
`[2026-08-28T21:45:00Z, 2026-08-29T21:45:00Z)`.

At observation time the expected current generation was G1:

* `nq-gh24-f249176c-observer@g1.service`: active/running;
* recurrence timer: enabled/active; recurrence service: inactive between
  bounded one-shot executions with latest result success;
* G2/G3/G4 observer timers: enabled/active for 03:45Z, 09:45Z, and 15:45Z;
* all three exact successor-handoff timers: enabled/active;
* closeout timer: enabled/active with next elapse
  `2026-08-29T21:45:05Z`;
* launch service: inactive/success; elapsed launch timer: disabled with no
  next elapse;
* G1 activation: armed with `finite_recurrence`; G2-G4 activations:
  staged/inert pending their exact handoffs.

The disclosed zero-attempt staging wake in
`staging-wake-observation.json` remains unchanged and must be carried into
the terminal classification.

Primary campaign-owned storage:

```text
/etc/nq-passive-24h-gh24-20260828-f249176c
  root:nq-passive-load-reader 0750, immutable configuration/control material

/var/lib/nq-passive-load/charter-gh24-20260828-f249176c
  nq:nq 0700, append-only ledgers and launch/closeout evidence

/var/lib/nq-passive-load/charter-gh24-20260828-f249176c/nq.db
  nq:nq 0644, SQLite evidence ledger

/var/lib/nq-passive-load/samples/gh24-20260828-f249176c-g1
  nq-passive-load-observer:nq-passive-load-reader 2750, retained G1 samples
```

G2-G4 have distinct campaign-owned sample directories and do not share mutable
current-state files with G1.

## Non-assertions

This handoff does not assert external reachability of wildcard listeners,
firewall policy, TLS routing, dashboard correctness, Prometheus scrape
configuration, public raw-evidence availability, equivalence between hostname
and substrate identity, whole-host health, a terminal 24-hour result, or that
pre-existing monitoring services observe this charter. It contains no
credential, private-key material, token, cookie, or authorization header.

## Closeout rendezvous

`READY`.

The finite child authority ends at `2026-08-29T21:45:00Z`. The loaded,
enabled closeout timer has an exact next elapse at
`2026-08-29T21:45:05Z`; its service is loaded and correctly inactive
before that boundary. The campaign closeout script and unit bytes are already
covered by `static-mechanics.sha256`. The terminal observer should rendezvous
after this timer, then perform the authorized read-only closeout audit and
preserve the separate terminal receipt. This readiness statement does not
predict success and does not substitute for terminal evidence.
