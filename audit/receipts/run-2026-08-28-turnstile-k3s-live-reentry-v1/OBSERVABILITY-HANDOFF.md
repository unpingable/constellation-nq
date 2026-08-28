# TURNSTILE observability handoff

Status: `INCOMPLETE`

Campaign: `TURNSTILE`

Slug: `k3s-ag-exact-occurrence-adapter-v1`

This is a descriptive handoff, not a receipt or qualification verdict. No
monitor, watcher, Role, RoleBinding, ClusterRole, or ClusterRoleBinding was
installed. Workload fields remain unknown because T10 stopped before T11 and
no TURNSTILE Pod was created.

At terminal closeout both campaign VMs are powered off. The facts below are
the final live observations before shutdown; the loopback endpoints no longer
listen. The checked qcow2 overlays and external evidence remain recoverable
under the campaign-owned lab root.

## Actual substrate facts

* control host: `crow`;
* kubeconfig: campaign-owned mode `0600`, API endpoint
  `https://127.0.0.1:16443`;
* k3s/Kubernetes: `v1.36.4+k3s1`, commit
  `4dedb15be78017a8ddd5b9e81acd44f3481078ed`;
* containerd: `2.3.4-k3s1.36`;
* cluster coordinate: kube-system namespace UID
  `729fc0ae-4c8a-407c-9c32-05aa54320ece`, API CA SHA-256 fingerprint
  `0E:39:F1:EC:27:D6:24:B6:AF:40:9C:63:BD:B0:47:04:5B:16:B2:DB:F5:C9:5D:61:CC:B5:F4:65:F8:0C:E7:D5`;
* node `turnstile-server`: UID
  `0680bf6e-9768-4552-afb0-6ce500e37550`, provider ID
  `k3s://turnstile-server`, internal IP `10.89.0.11`, Pod CIDR
  `10.42.0.0/24`, Ready;
* node `turnstile-agent`: UID
  `a0303433-733b-4f62-b211-6a761dd8c81e`, provider ID
  `k3s://turnstile-agent`, internal IP `10.89.0.12`, Pod CIDR
  `10.42.2.0/24`, Ready;
* namespace `turnstile-k3s-ag-v1`: UID
  `71792e3f-d491-4b67-8a98-221a7704f409`;
* service account `turnstile-exact-occurrence`: UID
  `0e3e40b3-deba-43b0-9a43-2d783e640a90`, token automount false.

The only Service/Endpoint pair is Kubernetes control-plane machinery:
`default/kubernetes` at `10.43.0.1:443` with endpoint
`10.89.0.11:6443`. The campaign namespace has no Service, Endpoint,
EndpointSlice, Pod, probe, restart count, or readiness condition to report.

## Retained volume facts

| Role | PV / UID | PVC / UID | Capacity | State |
| --- | --- | --- | --- | --- |
| canonical NQ custody | `turnstile-canonical-nq-custody-v1` / `e997c689-78ca-47de-908e-741e03cd3dd3` | `canonical-nq-custody` / `01fd0349-6121-43c3-811c-5495462dd145` | 100 GiB | Bound |
| external journal | `turnstile-external-journal-v1` / `662895b6-c596-4401-bf7d-00641e16b1b6` | `external-journal` / `e9338b94-c6d4-4edd-9ef8-c165ce1f5abd` | 10 GiB | Bound |
| terminal receipts | `turnstile-terminal-receipts-v1` / `503b400d-29d4-45f8-bdcd-de36e909c704` | `terminal-receipts` / `591ec4c0-d4e8-4b3f-a5e5-f41f496bef3b` | 10 GiB | Bound |

StorageClass `turnstile-external-retain-v1` has UID
`adfb0666-917e-4e47-b6b4-8165e2b8cfee`, provisioner
`kubernetes.io/no-provisioner`, `Retain`, and `Immediate` binding. The three
hostPath directories are backed by the campaign-owned crow filesystem through
the QEMU 9p tag `turnstile_custody`, so their bytes are outside Pod and guest
ephemeral state.

## Routes and boundaries

* the captured live topology exposed SSH only on loopback forwards
  `127.0.0.1:19221` and `127.0.0.1:19222`, and the API only on
  `127.0.0.1:16443`;
* each guest has restricted QEMU user NAT `10.0.2.0/24` for the control path;
* the node-to-node link is loopback-bound QEMU multicast on
  `10.89.0.0/24`;
* Flannel routes `10.42.0.0/24` and `10.42.2.0/24` across that link; and
* the observed Service range contains `10.43.0.1`.

No campaign service port or endpoint exists.

## Workload identity and non-assertions

Expected node, reported host, workload kind/name/UID, Pod UID, labels,
container ID, service/endpoints, probes, readiness, restart count, and mounted
volume observations are all `unknown` / `null`. The expected and reported host
identities must not be compared until AG authorizes an exact occurrence and
T10 supplies a qualified node-host acquisition contract. Kubernetes desired
state, node readiness, namespace possession, and PVC binding are not semantic
authorization.

## Candidate read-only RBAC (proposal only)

No RBAC below was installed. For the resources that actually exist now, a
candidate observer would require only:

* cluster-scoped `get/list/watch` for `namespaces`, `nodes`, `persistentvolumes`, and
  `storageclasses`; and
* namespace-scoped `get/list/watch` for `serviceaccounts` and
  `persistentvolumeclaims` in `turnstile-k3s-ag-v1`.

Pod, Pod status, Event, Service, Endpoint, EndpointSlice, probe, and restart
observation permissions are deliberately deferred because no such campaign
workload resources exist. If T11 is ever re-entered after T10 qualification,
this handoff must be updated immediately from actual object UIDs and only then
may a revised candidate RBAC proposal be derived. Installation remains a
separate decision.
