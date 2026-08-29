# CALIPER C3 fresh VM authority lifecycle

Campaign: `CALIPER`  
Slug: `passive-vm-release-reproducibility-and-lifecycle-v1`  
Parent campaign: `SOCKETWRENCH`  
Qualified release source: `e06a7b85699d23bbc0637fd4a1288f8c15afcbc8`  
C3 fixture commit: `e46f15a38030e720246909b70a114d265c0f08fc`

Classification:

`PASSIVE-VM-AUTHORITY-LIFECYCLE-NOT-QUALIFIED — PRE-AUTHORITY GENERATION-STORE MODE CONTRACT MISMATCH`

C2 remains independently
`PASSIVE-VM-RELEASE-REPRODUCIBILITY-QUALIFIED`. The predecessor's
`FIRST SAMPLE STORE ABSENT` result remains unchanged. No replacement C3 VM or
lifecycle run was created.

## Fresh target and exact release

Exactly one new disposable VM was created:

- environment ID `caliper-c3-vm-20260829`;
- OS hostname and `expected_reported_host` both exact `caliper-c3-vm`;
- Ubuntu 24.04.4, Linux 6.8.0-138-generic;
- KVM, two vCPUs, configured 2 GiB memory;
- fresh 20-GiB qcow2 overlay backed by immutable Ubuntu image SHA-256
  `d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30`;
- new cloud-init instance, SSH control identity, host-key binding, overlay,
  evidence root, sample root, signing key, and coordination naming cohort.

No predecessor identity or mutable state was reused. Before installation,
`nq-ng` was absent and relevant units were absent/inactive. The exact C2 Debian
package SHA-256 was
`7690816a1e574e32eb6606619bbed980ee3e6ea2469a745d685b065693c6566d`.
After inert installation, executable/unit digests matched C2, all packaged
services were inactive, and the timer was disabled.

Entry facts were two effective CPUs, 2063220736 observed memory bytes, no swap,
and 17871306752 free bytes at store readiness, above the 10737418240-byte guard.

## Exact pre-authority transition

Packaging owns the shared sample parent as
`nq-passive-load-observer:nq-passive-load-reader` mode `02750`. CALIPER's
fixture requested mode `0750` for its new G1 directory beneath that setgid
parent. Linux propagated SGID, so the actual dedicated directory was:

```text
nq-passive-load-observer:nq-passive-load-reader 02750
/var/lib/nq-passive-load/samples/passive-vm-release-reproducibility-and-lifecycle-v1-c3/g1
```

The product's bounded `generation-store-readiness` command succeeded and
reported generation
`sha256:4c32a1dd8ed83ad99054c7c8757a57d048a121d24c5722083dadbd05f443c53e`,
owner UID 985, reader GID 984, mode decimal 1512 (`02750`), free bytes
17871306752, and minimum 10737418240. It created no lock, sample, event, or
selection object.

The CALIPER fixture then refused because its pre-authority law required exact
mode `0750`. This was a fixture-level fail-closed assertion; the product command
did not refuse.

## Mode-law adjudication

Mode `02750` grants no group/other write permission. SGID preserves the already
intended reader group on descendants. It satisfies the implementation's
semantic predicate: a real, non-world-writable directory. The package's
deliberate `02750` parent makes this inheritance expected Linux behavior.

Qualified SOCKETWRENCH doctrine at `7a6b7c0`, however, states an exact dedicated
leaf mode of `0750`. Under that source law, `02750` is a deployment-contract
mismatch even though it is not an unsafe permission boundary. The readiness
implementation reports special bits but enforces only real-directory and
non-world-writable predicates.

The exact `0750` doctrine is thus more restrictive than packaging's natural
setgid inheritance and the implemented safety predicate. CALIPER does not
decide whether a successor should explicitly clear SGID or ratify a bounded
`0750`/`02750` mode set. It records the inconsistency and stops without changing
fixture, doctrine, packaging, or implementation.

## Authority counts

The refusal preceded NQ config/database initialization, recurrence policy
registration, enrollment, H creation, child issuance, admission, activation,
or recurrence-unit creation. Counts are:

- H: 0;
- G child issuances: 0;
- E enrollments/child issuances: 0;
- watcher/admission identities: 0;
- admissions/activations/samples: 0;
- recurrence attempts/acquisitions: 0;
- handoffs/successions/provider starts/fences/outcome-unknown: 0.

One pre-authority generation document and one unused signing key were prepared;
neither acquired H/G authority. Signing-key SHA-256 was
`6fc48ed126a6828790fdde6352a1c9006c37c74faae3fd140cfcebacf1b8ecc3`.
It was moved out of its live pathname and retained mode `000` only inside the
stopped overlay. The private-key-excluding evidence archive SHA-256 is
`8d2085425302f3afca26adafd585a54d932f97649a44281d4f4820a6ce88664e`.

## Closeout

- packaged services all `inactive`;
- `nqd.service` disabled;
- observer and recurrence services static/inactive;
- packaged recurrence timer disabled/inactive;
- campaign recurrence unit never created;
- live signing-key path absent;
- operating state directory empty; NQ database/config absent;
- VM powered off and controller SSH route closed;
- terminal overlay `qemu-img check`: PASS;
- serial-log SHA-256:
  `8b54c09df272bd4f7620f6d3ee3eda26514ab290aac202d6d18feb7372b05791`.

## GLASSHOPPER applicability

No live GLASSHOPPER access occurred. Existing repository evidence shows its
source `241af7c` does not contain later `7a6b7c0` exact-store doctrine, while
its handoff explicitly records live G1 mode `02750`. Its source accepts a real
non-world-writable store and has produced canonical samples.

CALIPER's mismatch is therefore a later SOCKETWRENCH deployment/doctrine
portability issue, not a shared defect in GLASSHOPPER's deployed exact source.
GLASSHOPPER was not failed, modified, accessed, or perturbed.

The descriptive handoff is `OBSERVABILITY-HANDOFF-READY`; it is not a verdict.
