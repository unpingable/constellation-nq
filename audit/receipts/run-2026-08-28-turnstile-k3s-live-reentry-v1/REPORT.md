# TURNSTILE k3s live re-entry V1

Campaign: `TURNSTILE`

Slug: `k3s-ag-exact-occurrence-adapter-v1`

Historical classification preserved:
`PASSIVE-K3S-AG-LIVE-NOT-QUALIFIED`

New bounded classification:
`PASSIVE-K3S-AG-LIVE-PREAUTH-QUALIFIED-ORIGIN-CAPACITY-BLOCKED`

| Gate | Classification |
| --- | --- |
| T7 disposable live substrate | `PASSIVE-K3S-AG-LIVE-ENVIRONMENT-QUALIFIED` |
| T8 immutable OCI custody | `PASSIVE-K3S-AG-LIVE-OCI-CUSTODY-QUALIFIED` |
| T9 retained external evidence | `PASSIVE-K3S-AG-LIVE-EVIDENCE-CUSTODY-QUALIFIED` |
| T10 portable node-host origin/capacity | `PASSIVE-K3S-AG-LIVE-ORIGIN-CAPACITY-NOT-QUALIFIED` |
| T11 smallest exact occurrence | `PASSIVE-K3S-AG-LIVE-OCCURRENCE-NOT-STARTED` |
| T12 live reconciliation cases | `PASSIVE-K3S-AG-LIVE-RECONCILIATION-NOT-STARTED` |

No AG authorization, NQ prepared occurrence, claim, Docket attempt,
Kubernetes workload, runtime occurrence, recurrence attempt, sample, or
acquisition was created. Kubernetes mechanics did not become semantic
authority.

## Source custody

TURNSTILE continued from qualified NQ source
`675e247e85d8e2e1f2801c06445bf863f82b3a5b` on branch
`campaign/k3s-exact-occurrence-adapter-v1`. T7 provisioning was committed at
`a44346c09f4a19ea7645597c76ee4bb6dbd9881c`; the deterministic OCI builder at
`38bb32736d93c7982adae9312b09125fbce63df3`; T9 filesystem custody at
`81269acea751c9040f10711a9fa0a5eba2cc28ef`, static retained volumes at
`d23724bc7749a34cf8db1b2e54885cc2145e48d7`, and bounded VM lifecycle fixes
through `7cfa51b6b0cfa56012d3cce9471bec8c62e2adac`.

The Linode artifact and other campaign tracks were not read, changed, or used
as custody. No unrelated VM, network, authority identity, or evidence store was
shared.

## T7 — disposable two-node k3s

Crow exposed `/dev/kvm` to the unprivileged campaign user. The campaign used
fresh qcow2 overlays over the previously qualified immutable Ubuntu 24.04
cloud base at SHA-256
`d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30`.
It did not change crow's privilege or authentication model.

| Node | Cloud instance | machine ID | Kubernetes UID | Capacity |
| --- | --- | --- | --- | --- |
| server | `k3s-ag-exact-occurrence-adapter-v1-server-adc1aa45-868d-4050-96f4-2d236605db88` | `f5b442c82e27444e8c088f71ee0c88f2` | `0680bf6e-9768-4552-afb0-6ce500e37550` | 2 CPU, 4009848 KiB memory, 29378688 KiB ephemeral |
| agent | `k3s-ag-exact-occurrence-adapter-v1-agent-865ad3e8-2963-4d96-b52b-cd5a55f87c13` | `adf354da69fa45fa85e482c359cd71ad` | `a0303433-733b-4f62-b211-6a761dd8c81e` | 2 CPU, 2977656 KiB memory, 23284224 KiB ephemeral |

Both nodes run Ubuntu 24.04, kernel `6.8.0-138-generic`, systemd 255, and
cgroup v2. Swap is zero. The private node link is `10.89.0.0/24`; SSH and API
forwards bind only to crow loopback. Kube-system UID is
`729fc0ae-4c8a-407c-9c32-05aa54320ece`. The API CA SHA-256 fingerprint is
`0E:39:F1:EC:27:D6:24:B6:AF:40:9C:63:BD:B0:47:04:5B:16:B2:DB:F5:C9:5D:61:CC:B5:F4:65:F8:0C:E7:D5`.

The official k3s `v1.36.4+k3s1` amd64 binary matched its published checksum
`835873f37245fc615f547a2fe2af9402a347875f13fa64a1f136de644955ea3f`
before and after installation. Server and agent unit SHA-256 values are
`8003cab81af7a67ef689a851e3066fb600b26e2772cda2877109ad3d7d5f646e`
and `cfe90828c5b6e876739b0869237c67e0a7d72a76aad56fe77daebf1ae289af14`.
The campaign kubeconfig is mode `0600`; its secret material is not reported or
committed.

## T8 — immutable OCI

Build invocation:

```text
cargo build --locked --release -p nq-app --bin nq -p nq-passive-load-helper --bin nq-passive-load-helper
scripts/build-turnstile-oci.sh
```

The OCI source commit is
`38bb32736d93c7982adae9312b09125fbce63df3`. Exact identities:

| Artifact | Digest |
| --- | --- |
| `nq` | `sha256:b56b39d2a3c3c689158d30db501f064bbe8696fcbfe8a6d3002808eddaee26e8` |
| passive helper | `sha256:62afc9479869a971e20eb26d2f136e3a01369c747c311c6377b2a715c1113f33` |
| OCI manifest | `sha256:ffd3c57744011b3234b2c383b12c1b47052d20b5b566938470bc71cea3a2832b` |
| OCI config | `sha256:608df10b3a41629bdbd6128729e4afeb010ad334a340085cd877001392033bcd` |
| OCI layer | `sha256:329a87e9ab218df9a6b5608b5f33b1292d2844ce5754688961d9204b7a255e3f` |
| OCI archive | `0686361426aa0a1b06f978fbe833b9a0d4d477aaac4cea430674d9b3687839b9` |

The immutable pull identity is
`turnstile.local/nq@sha256:ffd3c57744011b3234b2c383b12c1b47052d20b5b566938470bc71cea3a2832b`.
Both CRI stores resolve that exact repo digest to config
`sha256:608df10b3a41629bdbd6128729e4afeb010ad334a340085cd877001392033bcd`
and numeric user 65532. An authority-neutral containerd invocation returned
`nq 0.1.0` on each node. No Pod was used for this check.

The first CRI lookup refused because the OCI archive had been imported into
containerd's default namespace. Re-importing the same checked archive into the
inert k3s `k8s.io` namespace and adding the exact manifest-digest name repaired
only deployment context; no bytes or authority changed.

## T9 — retained external evidence

Manifest
`packaging/k3s/turnstile-retain-custody-v1.yaml` has SHA-256
`d8f6b1424a3edca53aea560d95301fd800acabee0b0014d443ef1a0a9cf391a2`.
It created one namespace, one token-less service account, one no-provisioner
Retain StorageClass, and three statically bound Retain PV/PVC pairs. Their
exact UIDs are recorded in `OBSERVABILITY-HANDOFF.md` and JSON.

The filesystem journal uses one immutable sequence pathname, `create_new`,
canonical JCS bytes, file `fsync`, then parent-directory `fsync`. It refuses
content mutation, gaps, symbolic-link root replacement, custody substitution,
and alternate concurrent-writer history. Thirty-two crate tests passed,
including four new filesystem qualification cases.

The authority-neutral live probe produced custody digest
`sha256:f213a10dd0361dd5d93cef0a1a6368298684148d6f852e497adddd3eb382a540`
and chain digest
`sha256:570104877c874c36435abf02aa3ea3d1579723d7757c86478237c4dbe1e3674d`.
Its immutable metadata and event files have SHA-256
`119e33a15f473d1a3c91443b56860da40eea80e4701e977802d1812dbc73e85f`
and `521b35befa26a1a34179762eeacf06c4b9a42b19ad51eb2b67eac50a74cb862e`.
Both nodes read those exact bytes as UID/GID 65532 and could not rewrite them.

Evidence reopened unchanged after the writer process exited, after the agent
k3s runtime service stopped/restarted, while the entire agent VM was powered
off, and after that exact overlay rejoined with the same Kubernetes node UID.
The first full-VM teardown attempt refused mechanically because `socat` was
absent; it did not stop the VM and was not counted. The fixture was narrowed to
the installed `nc -U`. A later clean shutdown exposed QEMU's normal removal of
its live pidfile; closeout now retains the already-captured PID explicitly.
Neither mechanical correction changed custody bytes.

## T10 — precise stopping condition

Raw facts are available: exact Kubernetes node UIDs/provider IDs, machine and
boot IDs, `/proc/1/status` CPU allowance `0-1`, cgroup-v2 collector paths,
`cpu.max` value `max 100000`, two effective CPUs, memory, and storage.
They are not sufficient to construct qualified
`nq.kubernetes_origin_capacity_facts.v1`.

The repository has a pure T2 validation model but no ratified Kubernetes
node-host acquisition contract, independently pinned collector/verifier, or
NQ recurrence integration for that role. Production recurrence accepts only
the qualified Linode origin profile and isolated Linode metadata helper. An
SSH shell observation cannot truthfully supply
`host_origin_contract_digest`, `acquisition_contract_digest`, exact procfs and
cgroup source identities, or a consequence-time capacity projection for the
future Pod resource envelope. Filling those fields from convenient hashes
would manufacture origin custody.

This is substrate-specific and is not a shared defect in the running Linode
charter. TURNSTILE therefore stops before T11. Re-entry requires ratification
and qualification of:

1. a Kubernetes node-host subject/scope/vantage and acquisition contract;
2. an independently pinned collector/verifier binding node UID, provider
   coordinate, procfs/cgroup-v2 source, and freshness;
3. consequence-time capacity projection for the exact Pod resource envelope;
   and
4. NQ recurrence integration that does not reinterpret the Linode profile.

No bare Pod, AG issuance, Docket attempt, or live reconciliation case may be
created until that contract passes.

## Terminal inert closeout

The final live read-only check found both nodes Ready, all three PVCs Bound,
and zero campaign Pods. The campaign namespace contained no Service,
Endpoint, Role, or RoleBinding, and no candidate observability RBAC was
installed.

`scripts/turnstile-k3s-lab.sh teardown` then stopped both campaign VMs using
their exact recorded QEMU PIDs. The three loopback forwards no longer listen.
`qemu-img check` reported no errors and `dirty flag: false` for both overlays:

| Overlay | Virtual size | SHA-256 |
| --- | --- | --- |
| `nodes/server/root.qcow2` | 30 GiB | `19c116b805cf1f7a612db1fe8cdad388dc966f7501702943a7e91e5edecd0a68` |
| `nodes/agent/root.qcow2` | 24 GiB | `93dd8acb62bf19d0421e5a665ffe1abbedc00ef31520e7d96f8937de8d7dc40d` |

The immutable base, checked overlays, campaign-owned mode-`0600` control
material, and external retain-all evidence remain recoverable under the
campaign lab root. Re-entry requires an explicit VM start and remains barred
from T11 until T10 qualifies. No unrelated VM was inspected or changed.
