# Substrate-origin V2 acquisition contract

## Standing

NQ V3 binds one independently signed origin attestation into the exact
acquisition intent before the observed provider is invoked:

```text
expected coordinate + exact acquisition basis
→ origin attester signature
→ immutable intent and provider-dispatch fence
→ provider intake
→ diagnostic admission provenance v3
```

The coordinate is an `attester_key` coordinate: canonical JCS bytes bind a
namespace, key ID, public-key digest, and the closed
`ed25519_acquisition_challenge` verification method. DNS, IP, hostname,
machine-id, boot ID, subject, producer, scope, and vantage are not coordinate
inputs.

This contract proves possession of the pinned attester key for the exact
acquisition basis before provider execution. It does **not** by itself prove
bare-metal identity, VM identity, installation identity, key/host co-location,
clone resistance, evidence truth, continuity, currentness, standing, or
authority. Those are explicit nonclaims in the signed object.

No production attester is qualified in this repository. Tests use an
in-process deterministic signer to qualify schema, signature, dispatch-order,
persistence, replay, and substitution behavior only.

## Candidate origin sources

The inventory below records why no existing local datum was silently promoted
to physical truth.

| Candidate | Producer / choosability | Lifecycle | Clone/collision | What it proves | Verification / TCB |
|---|---|---|---|---|---|
| Provider-signed instance identity | Provider; workload ordinarily cannot choose signed payload | Provider-defined across reboot/reimage/migration | Provider is responsible for uniqueness | Provider VM/incarnation under its stated contract | Offline signature or provider trust roots; no effect authority needed |
| Unsigned metadata instance ID | Metadata endpoint; host administrator can often proxy/spoof | Provider-defined | Clone behavior provider-specific | A response from a metadata path, not independent origin | Insufficient without authenticated transport/document |
| TPM quote/device key | TPM/hardware-backed key | Usually reboot-stable; reimage policy-dependent | Designed clone-resistant | Possession/state of a TPM identity and quoted measurements | TPM verifier and enrollment become TCB; not currently deployed |
| SMBIOS/DMI UUID | Firmware/hypervisor; often administrator-settable | Usually reboot/reimage-stable; migration/provider-dependent | Known clone/default collisions | Firmware/hypervisor label | Locally readable, not independently authenticated |
| `/etc/machine-id` | Installation tooling/root; freely copyable | Reboot-stable, normally changes on proper reimage | Common clone risk if images mishandle it | Installation label | Self-declared local state; raw value also has confidentiality guidance |
| App-derived machine-id | Local application from machine-id + app key | Same as machine-id derivation | Same clone boundary | Pseudonymous installation discriminator | Reduces disclosure, not self-assertion risk |
| Boot ID | Kernel boot instance | Changes every reboot | Can collide only under implementation failure | Boot, not substrate | Locally readable; wrong relation for this campaign |
| SSH host key | Host administrator/service | Reboot-stable; reimage/rotation/migration-dependent | Copyable across clones | Possession of one SSH private key | Valid endpoint authentication, not physical substrate |
| systemd service credential/principal | Deployment owner | Deployment-defined | Copyable unless hardware/provider-bound | Service/deployment identity | Useful custody, not substrate truth |
| Store genesis / NQ producer / subject / scope / vantage | NQ/deployment configuration | Intentionally portable | Reusable by design | Logical producer and evidence lineage | Already canonical; explicitly insufficient for substrate |
| DNS / hostname / IP | DNS/network/host configuration | Frequently changes or is reassigned | Reuse is routine | Naming or routing endpoint | Not canonical origin evidence |
| Kernel namespace/container ID | Kernel/runtime | Restart/recreate-sensitive | Runtime-specific | Process/container incarnation | Too narrow and often controller-visible/spoofable |

Most identifiers are non-confidential, but raw machine identifiers can be
sensitive. The V3 carrier exposes only a public-key digest and content-derived
coordinate; private key material never enters evidence.

## Coordinate semantics

`substrate_incarnation` V3 currently means one **attester-key custody
incarnation** under a pinned namespace and verification profile. That is a
portable protocol coordinate, not a claim of universal physical identity.

* Reboot: remains the same coordinate when the attester key remains the same;
  boot identity is separate evidence.
* Reimage: remains the same only if deployment deliberately retains the key;
  otherwise it is a new coordinate. Production policy must qualify which is
  intended.
* Provider migration: remains the same if key custody migrates; a provider
  attestation profile could instead choose provider-instance semantics.
* Clone: copying the key creates a collision. Preventing that requires a
  production attester whose key cannot be cloned or whose issuer detects it.

## Ordering, replay, and migration

NQ asks the origin source only after fixing acquisition ID, watcher instance,
configuration digest, subject, expected coordinate, and any exact Standing
continuity basis. It verifies the signed response, then atomically commits the
intent and `provider_invocation_started` fence before invoking the provider.
The completion event is appended only after provider intake is durable.

Exact replay returns the original diagnostic and does not re-attest or refresh
origin evidence. A started acquisition with unknown provider outcome refuses a
new logical acquisition. Schema-v6 to v7 migration creates empty origin tables;
it never synthesizes V3 proof for historical V1/V2 evidence.

Imported/cross-store diagnostic custody cannot acquire local origin standing.
The production admission export carries V3 only for locally committed origin
intent and exact phase history.
