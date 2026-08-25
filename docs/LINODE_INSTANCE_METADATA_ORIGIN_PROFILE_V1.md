# Linode instance-metadata origin profile V1

## Classification

**Origin contract qualified; deployment trust unqualified.**

`linode_instance_metadata_v1` is a closed profile for the existing NQ V3
substrate-origin carrier. It does not replace that carrier and it does not add
a second continuity protocol.

The profile proves this bounded proposition:

> A pinned origin helper reported that the fixed Linode instance-local
> metadata endpoint returned the exact logical Linode instance ID whose digest
> is committed in this acquisition's expected coordinate.

It does **not** prove physical hypervisor identity, guest installation
identity, boot identity, canonical subject identity, evidence truth,
currentness, standing, continuity authority, or effect authority. The metadata
document is not provider-signed portable attestation.

The current repository contains the closed schema, bounded parser, exact
profile verifier, acquisition binding, replay/substitution tests, and
Nightshift consumer. It deliberately does not ship or configure the
production-local fetch/sign helper. Helper isolation, executable custody,
metadata routing, service principal, and signing-key custody therefore remain
deployment qualifications.

## Provider mechanism actually established

Akamai documents its Metadata service as available only from within a
provisioned Linode and as returning only that Linode's instance and user data:

* <https://techdocs.akamai.com/cloud-computing/docs/overview-of-the-metadata-service>
* <https://techdocs.akamai.com/cloud-computing/docs/access-the-metadata-service-api>
* <https://techdocs.akamai.com/cloud-computing/docs/metadata-service-api>
* <https://techdocs.akamai.com/cloud-computing/docs/troubleshoot-metadata-service>

The fixed IPv4 endpoint is `169.254.169.254`. A caller first obtains a bounded
instance-specific token with `PUT /v1/token`, then supplies it as
`Metadata-Token` to `GET /v1/instance`. Akamai states that tokens from another
instance are rejected. The response is ordinary JSON over the instance-local
HTTP path. The documentation does not describe a provider signature over the
response.

The instance response currently contains `id`, `host_uuid`, `label`, `region`,
`type`, `tags`, `specs`, `backups`, `account_euuid`, and `image`.

## Coordinate

The canonical coordinate is:

```text
schema: nq.substrate_coordinate.v1
kind: linode_instance
namespace: akamai_linode
linode_instance_id_sha256: sha256(decimal provider instance ID)
evidence_method: linode_instance_metadata_v1
coordinate_ref: substrate:linode-instance:v1:<JCS digest>
```

Only the logical provider instance ID participates. Hashing limits incidental
identifier disclosure; it does not strengthen the provider assertion.

`host_uuid` is hashed into `nq.linode_instance_metadata_evidence.v1` as
supplemental provenance along with a digest of the complete canonical metadata
response. It is excluded from the coordinate because Akamai documents it only
as a host identifier and does not state a sufficient stability/non-reuse law.

`label`, region, plan type, image, account identifier, IP, DNS, OS hostname,
machine-id, boot-id, NQ subject, producer, scope, and vantage do not participate
in this coordinate.

## Relation meaning

For this profile only, `substrate_incarnation` means custody of one exact
logical Akamai/Linode instance coordinate. It does not mean physical
hypervisor placement or OS installation.

This is narrower than the English word “substrate,” but it is honest: the
relation is parameterized by the selected origin profile's separately
qualified proof strength. `software_attester_key_v1` proves key possession;
`linode_instance_metadata_v1` proves the bounded logical-instance proposition
above. Neither may substitute for the other.

## Lifecycle law

| Event | Logical instance coordinate | Other facts | Standing |
|---|---|---|---|
| Reboot | Same | Boot ID changes | No substrate succession under this profile. |
| Rebuild/reimage without resize | Same provider object/ID | Disks and configuration are replaced; installation identity changes | No logical-instance succession; this profile says nothing about installation continuity. |
| Resize | Same provider object/ID | Akamai states the Linode moves to a different physical host | No logical-instance succession; physical placement is outside the profile. |
| Live/warm/cold host migration | Same provider object/ID | Physical host may change; warm/cold may reboot | No logical-instance succession; `host_uuid` lifecycle remains supplemental/unqualified. |
| Cross-region migration | Same provider object/ID | Region and public addresses change | No logical-instance succession under this profile. |
| Clone to a new Linode | New target provider object/ID | Disk/config may be copied | New coordinate; configured identity equality cannot carry continuity. |
| Backup restore to an existing Linode | Same target provider object/ID | Installation/data may change | Same logical coordinate; installation semantics remain separate. |
| Delete and recreate | Expected new provider object/ID | DNS/label/IP may be reused | New coordinate when ID differs. Provider ID non-reuse over all time is not documented, so a same-ID reuse claim remains unqualified. |

The operation-path evidence for rebuild/migrate/resize targets the existing
`/linode/instances/{linodeId}` object. Akamai explicitly documents disk
replacement on rebuild and physical-host movement on migration/resize:

* <https://techdocs.akamai.com/linode-api/reference/post-rebuild-linode-instance>
* <https://techdocs.akamai.com/cloud-computing/docs/compute-migrations>
* <https://techdocs.akamai.com/cloud-computing/docs/resize-a-compute-instance>
* <https://techdocs.akamai.com/linode-api/reference/post-clone-linode-instance>

## Acquisition and trust boundary

The intended production helper is closed, not a generic HTTP client:

1. accept only the exact NQ acquisition basis;
2. obtain a short-lived token from the fixed link-local token endpoint;
3. GET only the fixed `/v1/instance` endpoint;
4. refuse redirects, oversized/malformed bodies, token failure, or endpoint
   substitution;
5. derive the logical-instance coordinate and supplemental response digests;
6. refuse unless it equals NQ's independently expected coordinate;
7. sign the exact acquisition basis plus typed metadata evidence with the
   pinned helper key;
8. return no general URL, command, shell, remediation, or monitoring surface.

NQ verifies that signed response and atomically persists it with
`provider_invocation_started` before invoking the observed provider. The
provider's own output cannot supply or override origin fields. Exact replay
returns the original result; it does not fetch new metadata or refresh origin
evidence.

Because the metadata response is unsigned, reliance also assumes Akamai's
instance-local routing guarantee and a helper/runtime isolation boundary that
prevents the observed workload from redirecting the fixed endpoint or using
the helper key elsewhere. Those assumptions are not yet qualified on the real
host.

## Bootstrap

Nightshift's genesis is an exact deployment-owned
`bootstrap_coordinate_ref`, not “the first coordinate observed.” For this
profile it must be computed from an independently authorized/pinned Linode
instance ID before admission. Runtime metadata may prove equality with that
pin; it may not create the pin it is asked to prove.

The live reconnaissance did not use a Linode control-plane credential, so the
real host still lacks that independent bootstrap basis. No imaginary `P0` is
introduced.

## Read-only live witness (2026-08-24)

Using the pre-existing SSH key and already-known host key with strict checking,
read-only requests to the existing Linode established:

* the token endpoint returned a 64-byte token;
* `/v1/instance` returned HTTP 200, JSON, and the documented field family;
* sensitive provider IDs were retained only as local SHA-256 observations;
* the response reported region `ca-central`, type `g6-dedicated-4`, and image
  `linode/ubuntu22.04`;
* OS hostname remained `localhost`; machine-id, boot-id, DNS names, and NQ's
  logical source name remained different semantic layers.

This witness proves endpoint availability and response-shape correspondence at
one time. It is not a governed admission, bootstrap, helper-isolation proof, or
current production observation.

## Deployment gates

Before real admission:

1. ratify the governed subject separately from provider coordinate and names;
2. independently pin the exact logical Linode instance-ID digest for genesis;
3. implement and custody the fixed-endpoint helper executable;
4. run it under a dedicated service principal isolated from the observed
   workload and NQ daemon/operator identity;
5. qualify its key custody, file ownership/modes, restart/replay, token
   handling, and endpoint non-redirection;
6. configure Nightshift's exact profile and V3 downgrade gate;
7. retain credential rotation/revocation, live backup, disk-full/power-cut, and
   designated-host source-honesty claims as separate environmental gates.

No installation, configuration, service activation, key enrollment, or
production cutover was performed by this campaign.
