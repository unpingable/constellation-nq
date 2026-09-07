# Operator-beta NQ-ng observation helper checkpoint

**Status:** `IMPLEMENTATION_CANDIDATE_READY_FOR_INDEPENDENT_AUDIT`
**Qualified implementation subject:** `333d0bcc911245a1a137e9a124a61113b765e9bb`
**Tree:** `0d8853267df8631a72cc2c1d5e30f1a7a4bf7aad`
**Accepted contract parent:** `e45c7b4bfb18ea740576a65f692b29f4390fbaff`

## Observed implementation

The new package-local binary `nq-operator-beta-helper` implements only the accepted
`nq.systemd_unit/v1` and `nq.http_endpoint/v1` acquisition branches over the existing
strict NQ helper protocol. It has no dependency on `nq-core`, `nq-store`, or `nq-app`
and owns no scheduling, admission, policy evaluation, persistence, retry, composition,
authority, or effect semantics.

The systemd branch uses one zbus system-bus connection and, within the request's Linux
boottime deadline, orders `GetMachineId -> RefUnit -> GetUnit -> GetUnitFileState` before
the four exact unit-property reads. It requires the live machine identity and bounded
no-follow regular-file SHA-256 to equal the exact request scope before emitting testimony.

The HTTP branch accepts one numeric-address plain-HTTP `GET /healthz` on port 18080,
follows no redirect, and admits only one final HTTP/1.0 or HTTP/1.1 response with one
canonical `Content-Length`, no `Transfer-Encoding`, a 16,384-byte header limit, and an
exact declared body within the scope bound.

Malformed/common-invalid input and an unrepresentable echo produce bounded stderr, nonzero
exit, and no stdout. An external acquisition failure instead produces one valid failed
report with unavailable coverage, no observation, and one bounded typed error. The helper
does not convert absence of testimony into a negative postcondition.

## Qualification evidence

- Focused helper suite: 12 library and 3 binary cases passed.
- Exact minimum bounds and every one-below-minimum substitution passed.
- Profile digest, capability, deadline, malformed-frame, unrepresentable-response, numeric
  endpoint, HTTP framing/body, unit-file bound, and final-component symlink cases passed.
- Full locked workspace: 437 passed; one intentional maintainer fixture emitter ignored.
- All-target/all-feature workspace Clippy with `-D warnings`: passed.
- Workspace formatting: passed.
- `scripts/check_operator_beta_helper_boundary.sh`: passed.
- Its deterministic missing-`RefUnit` control exited nonzero with the expected boundary
  message.

The structural gate enforces the accepted call sequence, file bound/no-follow law, forbidden
mutation/subprocess vocabulary, HTTP framing constants, and absence of NQ scheduling/store
dependencies. Runtime and gate were corrected together when pre-freeze review found the
initial `GetUnitFileState` ordering mismatch.

## Unqualified dimensions

No live system-bus acquisition, package build/install/remove/reinstall, Debian 12 VM run,
two-VM HTTP acquisition, provider-intake persistence, diagnostic-artifact emission, Docket
association, post-effect observation, service activation, production deployment, or
general NQ-ng cutover was performed. Those remain later M1B qualification gates.

Classic NQ remains preserved and `SUPERSEDED_FOR_OPERATOR_BETA`; no classic code, result,
or acceptance was imported. This checkpoint qualifies nothing until independent audit
accepts the exact subject. Even if accepted, it establishes only the bounded one-shot helper
implementation, not the complete M1B profile/package/VM result.
