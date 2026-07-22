# Provider-intake foundation operator ratification

Date: 2026-07-22

Operator act: **RATIFY-PROVIDER-INTAKE**

Verdict: **PROVIDER-INTAKE-RATIFIED**

This is a separate immutable operator-decision record over the completed
provider-intake qualification. It does not edit, replace, or reinterpret the
qualification receipt whose terminal verdict remains
**READY-FOR-PROVIDER-INTAKE-RATIFICATION**.

## Exact ratified object

The operator ratifies the bounded post-release provider-intake foundation at:

- branch at ratification: `campaign/provider-intake-foundation`;
- technical candidate commit:
  `44e556709e629eb3c83d1d74bfbcf12cb4c9a549`;
- candidate tree:
  `9aee37f90b93f27296550d9664af5ec574e5bf27`;
- candidate parent:
  `e3c451f9722cb81dd22af25c52b264e6b888ed81`;
- qualification record-only commit:
  `ef7e1b8561484cb27faaa9f2e5b052d3fb937e7c`;
- qualification record-only tree:
  `484f8528bcd102b46fdb8e505a5889d831b46abe`.

The immutable qualification receipt is
`audit/receipts/run-2026-07-22-provider-intake-foundation/RECEIPT.md`, SHA-256
`a37f01aeed1bbae93a5d9125fa3a3d374dcacee7024a3be8fb1f7e46f0df13a2`.

## Bound qualification evidence

Ratification is bound to these exact independently qualified objects:

- rebuilt package:
  `/home/jbeck/nqlab/nq-ng-provider-intake-artifacts/44e5567/release/nq-ng_0.1.0_amd64.deb`;
- package SHA-256:
  `4f078257b2a23dd06f51ec3e2376b16973d247d0f0be9e6d14c6325f04d9408f`;
- clean-pinned audit ledger JSON SHA-256:
  `bb1a8fad28bde6b4d4d6a3f7f581be54c70c7ee7b2955da3703ade19e94c36e2`;
- clean-pinned audit ledger Markdown SHA-256:
  `4b5ff168254402f16a2e8352b76c82ac4284ae55482beb84b836ebc9d0524b33`;
- fresh KVM qualification:
  `/home/jbeck/nqlab/nq-ng-hardening/run-2026-07-22-44e5567`;
- evidence-manifest SHA-256:
  `b8262fdd58c99ca0f0c21ac8dff6017214289d0edbf33ce1d685467a6ddae4f1`;
- sealed inventory: 51 exact entries, including mandatory
  `guest-results/RESULT`;
- VM verdict: `result=pass`;
- staged VM package `nq-ng.deb` SHA-256:
  `4f078257b2a23dd06f51ec3e2376b16973d247d0f0be9e6d14c6325f04d9408f`.

The audit passed all three active controls with zero waiver or obstruction and
2/2 semantic mutations biting. The KVM run passed all four mandatory markers,
independent guest admission, and exact evidence-seal reopening. Package bytes
were identical before and after qualification.

## Decision and bounded meaning

The operator accepts that evidence as sufficient to ratify the exact technical
candidate as the provider-intake foundation. The foundation may therefore be
used as the accepted post-`v0.1.0` baseline for separately authorized future
work.

This decision ratifies only the implemented NQ-specific, local-helper boundary:
independently bound provider identity, exact native outcome and raw custody,
provider admission distinct from report admission, exact replay, atomic
durable acknowledgment, honest schema-v3 history gaps, and schema-v4 backup,
restart, archive, and historical reopening.

Ratification is not a new release qualification and does not turn the external
package into a tagged or published release. It does not expand the qualified
claim beyond the candidate, package, audit ledger, and KVM run named above.

## Preserved release and non-claims

The separately minted release remains unchanged:

- local tag `v0.1.0` resolves to
  `2c41b0a49f9dc0e4e1b6c4da7863353d28ea6a5d`;
- tagged tree:
  `f7f244d69461e342997850869cb243abdbdedf27`;
- `dist/nq-ng_0.1.0_amd64.deb` SHA-256:
  `24ca5e0b40d9fde5a51c7324d27c3d83d3386669a833c23db773f49840141e63`.

No post-`v0.1.0` tag, push, publication, upload, or remote configuration is
authorized or performed by this decision. It creates no JCP extraction, AG
integration, physical watcher split, remote provider, eBPF provider, action
authority, or broader provider-neutral intake claim.
