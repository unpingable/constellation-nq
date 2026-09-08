# Operator-beta NQ-ng observation helper checkpoint

**Status:** `LIVE_RUN_005_REFUSED__CORRECTION_ACCEPTED_PUBLISHED`
**Accepted correction result:** `c62eb7130c813896903e0156bd0593e22befe4a5`
**Accepted correction tree:** `110d5becd3613cdae479c33df7f681aa77545da9`
**Correction implementation candidate:** `860452c53d63b6162c18a2e0b4aba4acb736baea`
**Correction tree:** `083a6a9c52ba49f1f2cd181c3793941f894b3212`
**Correction parent:** `1cc635cc3dd8ac092d1ea9b1d772a06ee0d80cc5`
**Accepted predecessor qualification:** `9d8624a2d13cb1562b55a81de6f6cea07fb65dcc`
**Accepted predecessor implementation:** `386358190e974c532d5237d36231fe7e806d100e`
**Accepted contract ancestor:** `e45c7b4bfb18ea740576a65f692b29f4390fbaff`

## Observed implementation

The new package-local binary `nq-operator-beta-helper` implements only the accepted
`nq.systemd_unit/v1` and `nq.http_endpoint/v1` acquisition branches over the existing
strict NQ helper protocol. It has no dependency on `nq-core`, `nq-store`, or `nq-app`
and owns no scheduling, admission, policy evaluation, persistence, retry, composition,
authority, or effect semantics.

The accepted helper used one zbus system-bus connection and ordered
`GetMachineId -> RefUnit -> GetUnit -> GetUnitFileState`. Fresh M1B run-005
mechanically demonstrated that unprivileged `nq-helper` receives
`Interactive authentication required` for `RefUnit`; the retained exact helper
response therefore correctly reported `systemd_unit_reference_failed`, and NQ
correctly refused to infer complete testimony. No effect was attempted.

The bounded correction replaces that authorization-bearing call sequence with
`GetMachineId -> ListUnitsByNames -> ListUnitFilesByPatterns`. The two latter
unprivileged manager observation calls return one exact stable runtime-state row and one exact
unit-file path/state row for the same unit name. Cardinality, unit identity,
alias/following, and in-progress-job disagreement refuse. The helper still
requires the live machine identity and bounded no-follow regular-file SHA-256
to equal the exact request scope before emitting testimony.

Upstream systemd v252 commit
`e8dc52766e1fdb4f8c09c3ab654d1270e1090c8d` shows
`method_list_units_by_names -> bus_load_unit_by_name`; the latter may internally
instantiate or load unit metadata while answering `ListUnitsByNames`. This
bounded measurement-side manager-state change is part
of the observed behavior, not a unit job or evidence of enactment. The helper
requests and retains no explicit unit reference, accepts only a job-free row,
and has no start, stop, restart, reload, or cache-lifetime authority.

The HTTP owner profile and helper accept one numeric-address plain-HTTP
`GET /healthz` on port 18080 and refuse hostname or wrong-port bindings before
acquisition. The helper follows no redirect and admits only one final HTTP/1.0 or
HTTP/1.1 response with one canonical `Content-Length`, no `Transfer-Encoding`,
closed ASCII header syntax, a 16,384-byte header limit, an exact declared body
within the scope bound, and bounded EOF after that body.

Malformed/common-invalid input and an unrepresentable echo produce bounded stderr, nonzero
exit, and no stdout. An external acquisition failure instead produces one valid failed
report with unavailable coverage, no observation, and one bounded typed error. The helper
does not convert absence of testimony into a negative postcondition.

## Qualification evidence

- Focused helper suite: 13 library and 3 binary cases passed.
- Exact minimum bounds and every one-below-minimum substitution passed.
- Profile digest, capability, deadline, malformed-frame, unrepresentable-response,
  hostname and wrong-port pre-acquisition refusal, generic malformed-header,
  split-write trailing-body, numeric endpoint, HTTP framing/body, unit-file bound,
  and final-component symlink cases passed.
- Full locked workspace: 438 passed; one intentional maintainer fixture emitter ignored.
- All-target/all-feature workspace Clippy with `-D warnings`: passed.
- Workspace formatting: passed.
- `scripts/check_operator_beta_helper_boundary.sh`: passed.
- Its deterministic missing-manager-list control exited nonzero with the expected boundary
  message.

For the bounded correction, 15 helper library cases and three binary cases
passed; the full locked workspace passed with the one documented maintainer
fixture emitter ignored; all-target/all-feature workspace Clippy with
`-D warnings`, formatting, and the corrected boundary gate passed. The gate's
missing-`ListUnitsByNames` control refused deterministically.

A disposable snapshot-only local VM reopened the stopped run-005 target disk
without modifying the terminal occurrence. Under the real unprivileged
`nq-helper` UID, the corrected binary consumed the exact retained helper
request binding with only a fresh request identity and boottime deadline. It
emitted one complete report with complete coverage, no errors, and the exact
inactive/dead/disabled state, object path, machine identity, and unit-file
digest. The VM was then powered off. This checks the corrected permission
boundary; it does not relabel run-005 or qualify the full M1B journey.

The independent audit of `0fe03f50ff971d910ff61f3ed2dd5d6534e67ab7`
returned `NOT_ACCEPTED / CORRECTION_REQUIRED`: the owner binding accepted hostname
and wrong-port locators, and exact response closure depended on TCP segmentation
while generic header syntax was unchecked. Subject `386358190e974c532d5237d36231fe7e806d100e`
closes those two bounded findings without adding storage, evaluation, or authority.

The structural gate enforces the bounded unprivileged manager observation
sequence, explicitly forbids `RefUnit`, `LoadUnit`, unit-job methods, and
subprocess mechanics, requires the job-free row checks, preserves the file
bound/no-follow law and HTTP framing constants, and checks the absence of NQ
scheduling/store dependencies.

Independent audit rejected exact qualification-binding subject
`a861875f6c9083d0ef25826a7a116ab84f5c49d6`: its runtime boundary was job-free
and unprivileged, but the documents and gate incorrectly equated the absence of
an explicit `LoadUnit` call with absence of any manager-state change. This
non-rewriting correction preserves the implementation and records systemd
v252's possible internal metadata load without promoting it into an effect or
authority claim.

Independent re-audit accepted exact correction subject
`c62eb7130c813896903e0156bd0593e22befe4a5`; local, tracking, and remote branch
refs were then verified equal to that subject. This accepts the bounded helper
correction only. It does not qualify a fresh package or M1B run.

## Unqualified dimensions

The accepted predecessor performed no live system-bus acquisition. The bounded
correction used only the disposable snapshot check described above. No corrected
package build/install/remove/reinstall, fresh two-VM M1B run, HTTP acquisition,
provider-intake persistence, diagnostic-artifact emission, Docket association,
post-effect observation, service activation, production deployment, or general
NQ-ng cutover was performed. Those remain later M1B qualification gates.

Classic NQ remains preserved and `SUPERSEDED_FOR_OPERATOR_BETA`; no classic code, result,
or acceptance was imported. Independent audit accepted exact qualification result
`9d8624a2d13cb1562b55a81de6f6cea07fb65dcc` for implementation
`386358190e974c532d5237d36231fe7e806d100e`. That result establishes only the bounded
one-shot helper implementation, not the complete M1B profile/package/VM result.
