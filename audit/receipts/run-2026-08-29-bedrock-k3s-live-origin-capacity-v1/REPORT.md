# BEDROCK B3/B4 live substrate and origin/capacity qualification

Campaign: `BEDROCK`
Slug: `k3s-live-origin-capacity-qualification-v1`
Date: 2026-08-29

## Independent classifications

| Bounded phase | Classification |
| --- | --- |
| B3 live substrate recovery/recreation | `PASSIVE-K3S-BEDROCK-LIVE-SUBSTRATE-REQUALIFIED` |
| B4 live origin/capacity preflight | `PASSIVE-K3S-AG-LIVE-ORIGIN-CAPACITY-QUALIFIED` |
| B5 first live exact occurrence | not started |
| B6 reconciliation qualification cases | not started |

These are BEDROCK classifications. They are not an aggregate result and do not
alter TURNSTILE, CALIPER, SOCKETWRENCH, or GLASSHOPPER custody.

## Source and artifact custody

BEDROCK began at TURNSTILE terminal commit
`1dbae78451abb6958bb30b94c65cacbd0666ef0e`. The deferred Stage-A law was
qualified at `a107ac5b2bef3e09b65f47be6a79fb831381ef9e`; explicit API-node versus
OS-hostname binding at `8b6b3267b599091214e183f96c51907967433369`; independent
live verifier at `24272bd31b8f334108249b5fa3c1896dee68d1e1`; and the
campaign-owned cluster/image representation at
`b42c1259f27d9caaf06de60eaa8c10fbeb051125`.

The immutable OCI artifact was built from
`b42c1259f27d9caaf06de60eaa8c10fbeb051125`:

- reference:
  `bedrock.local/nq@sha256:c57aa0eca562425a8038e323d968af206f4d2eae6eec112d4c126cea56dce33d`;
- OCI archive SHA-256:
  `03cf1f9d847b30139d70090a33602bcbcdc9ac5af12dd181d78e8d0981565c47`;
- image configuration:
  `sha256:7190e6d3c3dede7a1402a3d6031a627e5c9f62182ea52931ea43fdee7cc8570d`;
- NQ executable:
  `sha256:b60f16228c3e821c4390c5d863977ec4d7f3487913592afdcdbded36df3da489`;
- passive helper:
  `sha256:e85c4b36d8c07e7be95a6c36072db45f6cae47d1415698c5beec27d1e7d5964e`.

Both k3s containerd stores retained the exact digest-addressed image after the
agent VM reboot and the server service restart. No mutable image tag was used
as the admitted artifact identity.

The one-shot observer SHA-256 was
`0e2e2bb27456bf69af4c0b3fd8de4c4ad9f27c1204b4519871732819471f10c5`.
The controller-side verifier SHA-256 was
`403cde4fa5b83b34091bc41c6606a1668d5eddf7bf72950ce4d895d9b33faa39`.

## B3 campaign-owned cluster

The predecessor cluster was not copied because that would copy TURNSTILE
credentials and mutable cluster state. BEDROCK created fresh overlays from the
same checked immutable base and generated fresh SSH, k3s token, API CA, and
kubeconfig custody.

- Kubernetes/k3s: `v1.36.4+k3s1`;
- containerd: `2.3.4-k3s1.36`;
- cluster coordinate: kube-system namespace UID
  `d29b8fe6-b11a-46ce-be34-3c1e949867fd`, API CA DER SHA-256
  `dcb0b34d40e5c11f86c9d44cbe9249fb7353e7d28cab12e3d5dbdb068c276d22`;
- campaign namespace UID:
  `bedrock-k3s-ag-v1` /
  `d0f72e14-4d14-4001-a4dc-20b3e7008322`;
- token-less service account UID:
  `bedrock-exact-occurrence` /
  `b31bb029-c5ad-4437-8fda-6af4c2f724ca`.

Node coordinates at terminal B4 observation:

| API node | API/OS reported hostname | Node UID | Machine ID | Boot ID | Capacity |
| --- | --- | --- | --- | --- | --- |
| `bedrock-server` | `bedrock-k3s-server` | `d76c71db-a442-4661-b895-f1e434c00b78` | `9acf22c610fb4c85af57e6d5952d57fc` | `07e12578-8c4e-4808-b825-280085f137e2` | 2 CPU, 4009860 KiB memory |
| `bedrock-agent` | `bedrock-k3s-agent` | `462df906-509f-4e6b-b7f6-2a9951e373fc` | `32b4cd9c15cf465a95e87e1de847a332` | `c83b2deb-64e1-4939-94cf-37488ac3c4c9` | 2 CPU, 2977656 KiB memory |

All MemoryPressure, DiskPressure, and PIDPressure conditions were false.
Kubernetes API object names are exact placement identities; the distinct
Hostname address/OS hostname is an independently bound reported identity. No
alias substitution was made.

## T9 retained external evidence requalification

StorageClass `bedrock-external-retain-v1` has UID
`c6289578-beba-4c56-a124-017f31b54cd9`, no provisioner, Immediate binding,
and Retain policy. The exact Bound pairs are:

| Role | PV / UID | PVC / UID | Declared capacity |
| --- | --- | --- | --- |
| canonical | `bedrock-canonical-nq-custody-v1` / `b9e22f58-6f9b-40aa-9de4-f85713258b89` | `canonical-nq-custody` / `bcd8954c-d576-4896-9fc8-517ea563b06f` | 100 GiB |
| journal | `bedrock-external-journal-v1` / `17cd29c6-7316-4810-878f-aadd1b3a7350` | `external-journal` / `385edb17-6cbf-45b0-97eb-a5dcea79d15a` | 10 GiB |
| receipts | `bedrock-terminal-receipts-v1` / `b684134c-6a99-445b-8222-d1d9e5ae7151` | `terminal-receipts` / `b0d1d760-36cd-41f1-9635-617a8719de5b` | 10 GiB |

The runtime directories are owned by numeric service identity 65532:65532,
mode 0700. The authority-neutral BEDROCK journal probe appended on the rebooted
agent and reopened exact bytes on the server:

- custody digest:
  `sha256:779dcd926be724d47a981539453a5683fdd454ab298f463553ef797b155aeeec`;
- chain digest:
  `sha256:507424cd12cd662187e00815d31210fc0e8d4d9bd1a87d39140bd536e9c5fbf4`;
- immutable custody file:
  `361d035aff4bbe8551b69ec5c8c65ffeb2a9af341a30306376292c1b76d4e2ed`;
- immutable event file:
  `7ea05c71adbfa859d7988ab447d14c13a83a94144aa36242ed0d0627a0902e68`.

The files remained exact across node-local runtime loss, the agent VM reboot,
shared storage remount, and server control-plane restart.

## B4 exact Stage-A qualification

The content-bound mechanics policy has SHA-256
`26120d03a506433c158bf4ff5782ea66f161d34302b6ea30673708c8c5371e87`.
It fixes a bare ownerless Pod representation, cardinality one,
`restartPolicy: Never`, fixed placement, no rescheduling, a digest-addressed
image, and three exact retained PVCs. It is non-authorizing.

The server signed observation qualified with:

- contract SHA-256:
  `bd00bcff5e0ec3bbbbf663201088283ea3379fddd62d503300ec1b0f11759ae8`;
- signed observation:
  `sha256:eafe8d60f753e76d87ee1187934d1f26775ffe48b06cfc39e73770ce153c4cb8`;
- pre-runtime context:
  `sha256:a9aa15dcad1a601e03dcf043fcce41c77dcb6ccb7aa8e48b98aa4ea84e40f58c`;
- placement:
  `sha256:d7443d597b7b44e82d7c0c25099645fbc6543be9d2b1317be1e2db227236d5fd`;
- 2 available CPUs and 824435015680 storage bytes available.

The first agent signed observation qualified before reboot. Reboot preserved
the node UID and machine ID but changed boot ID from
`f019e9a3-f5db-47dd-bc2f-ccfbafedb752` to
`c83b2deb-64e1-4939-94cf-37488ac3c4c9`. A freshly timed basis retaining the
old boot identity produced signed node facts but the independent verifier
refused it with `signed observation content`. A new basis bound to the new
boot identity qualified with:

- contract SHA-256:
  `840cfc43e768cddb56db01c3d03b58727051169548bab925a91c3c749991d8af`;
- signed observation:
  `sha256:bf946253b94a2ec51d93bc8fb73eb9722175d257cb2b4c0909a3fb278d0f2424`;
- pre-runtime context:
  `sha256:df8d3055ccb92735f0245a9e8faa9a7bbc8fa2c6bc2b69fcd1476493350301fc`;
- placement:
  `sha256:8fa7f80842f5fb9aaf4fa0d58aa905e938be6fc6e6bc27d5e3c83f62ac58e08b`;
- 2 available CPUs and 824612749312 storage bytes available.

The first authority-neutral observer call used a noncanonical projection
schema value and refused `acquisition contract`; the exact closed
`nq.bedrock_unlimited_cpu_runtime_projection.v1` value then qualified. An
initial post-reboot negative-control acquisition also refused its freshness
window because the node clock was measured approximately 0.5 seconds behind
the controller. The repeated request window explicitly included that measured
offset; it then isolated and proved the boot-identity refusal. Neither
mechanical refusal created a workload, authority, claim, fence, or execution.

Every qualified Stage-A output carries mandatory deferred obligations for
actual Pod UID, container ID, procfs, cgroup, available parallelism, and the
claim/fence-before-release transition. Therefore this result proves a
content-bound pre-runtime plan; it does not claim that consequence-time
workload facts already exist.

## Exact zero-authority gate

At B4 completion:

- Kubernetes Pods across all namespaces: 0;
- campaign Services, Endpoints, and EndpointSlices: 0;
- AG authorizations: 0;
- NQ occurrences: 0;
- prepared authority objects: 0;
- execution claims/releases: 0;
- provider starts: 0.

No bootstrap Pod was created. B5 may begin only from a fresh exact
authorization and while its Stage-A context is valid or freshly reacquired.
