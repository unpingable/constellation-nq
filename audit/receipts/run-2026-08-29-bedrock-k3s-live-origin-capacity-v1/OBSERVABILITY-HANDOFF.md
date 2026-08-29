# BEDROCK observability handoff

Status: `OBSERVABILITY-HANDOFF-INCOMPLETE — actual workload identity, Pod UID, runtime routes/probes/restarts, volume attachment, and workload-specific minimum RBAC are not knowable before B5 creates the first authorized workload`

This artifact describes what was deployed and where it may be observed.
It does not establish monitor health, NQ disposition, deployment
qualification, authorization, or semantic correctness.

## Identity

- Environment: `BEDROCK / k3s-live-origin-capacity-qualification-v1`.
- Cluster coordinate: kube-system UID
  `d29b8fe6-b11a-46ce-be34-3c1e949867fd` plus API CA DER SHA-256
  `dcb0b34d40e5c11f86c9d44cbe9249fb7353e7d28cab12e3d5dbdb068c276d22`.
- Node `bedrock-server`: UID
  `d76c71db-a442-4661-b895-f1e434c00b78`, IP `10.90.0.11`,
  OS/API-reported hostname `bedrock-k3s-server`.
- Node `bedrock-agent`: UID
  `462df906-509f-4e6b-b7f6-2a9951e373fc`, IP `10.90.0.12`,
  OS/API-reported hostname `bedrock-k3s-agent`.
- Configure `expected_reported_host=bedrock-k3s-server` for the server node
  and `expected_reported_host=bedrock-k3s-agent` for the agent node.
- Identity check: declared and actually reported strings matched exactly on
  both nodes. Kubernetes placement names `bedrock-server` and
  `bedrock-agent` are distinct API identities and are not aliases.
- No stable DNS names are configured.

## Access

- Kubernetes API: controller-host loopback
  `https://127.0.0.1:17443`; private/local control route; credentials are
  required and are deliberately absent from this artifact.
- API health surface: `/readyz` on that authenticated API route.
- Node addresses `10.90.0.11` and `10.90.0.12` are private
  campaign-network addresses.
- SSH forwards `127.0.0.1:19321` and `127.0.0.1:19322` are
  campaign-control routes, not monitor endpoints.
- No HTTP application, Prometheus, exporter, or monitor-specific agent route
  is installed.
- Network boundary: the node addresses are not public or LAN-routed; an
  observer outside the controller host has no route in the current lab.

## Kubernetes

- Namespace: `bedrock-k3s-ag-v1`, UID
  `d0f72e14-4d14-4001-a4dc-20b3e7008322`.
- ServiceAccount: `bedrock-exact-occurrence`, UID
  `b31bb029-c5ad-4437-8fda-6af4c2f724ca`, token automount disabled.
- Workload kind/name/UID: null; intentionally nonexistent through B4.
- Pod names/UIDs: null.
- Stable workload labels/selectors: null until the exact B5 projection exists.
- Desired replicas: not applicable; no controller exists.
- Service/Endpoint/EndpointSlice: none.
- Readiness/liveness probes: none.
- Pod readiness/restarts/waiting reasons: not applicable.
- Both Kubernetes Nodes were Ready at handoff time; all reported pressure
  conditions were false.

## Persistent storage

StorageClass `bedrock-external-retain-v1`, UID
`c6289578-beba-4c56-a124-017f31b54cd9`, is no-provisioner/Retain/Immediate.

- `canonical-nq-custody` UID
  `bcd8954c-d576-4896-9fc8-517ea563b06f` is Bound to
  `bedrock-canonical-nq-custody-v1` UID
  `b9e22f58-6f9b-40aa-9de4-f85713258b89` at
  `/mnt/bedrock-custody/canonical`.
- `external-journal` UID
  `385edb17-6cbf-45b0-97eb-a5dcea79d15a` is Bound to
  `bedrock-external-journal-v1` UID
  `17cd29c6-7316-4810-878f-aadd1b3a7350` at
  `/mnt/bedrock-custody/journal`.
- `terminal-receipts` UID
  `b0d1d760-36cd-41f1-9635-617a8719de5b` is Bound to
  `bedrock-terminal-receipts-v1` UID
  `b684134c-6a99-445b-8222-d1d9e5ae7151` at
  `/mnt/bedrock-custody/receipts`.

No volume is attached to a workload yet.

## Host/runtime

- Server systemd unit: `k3s.service`.
- Agent systemd unit: `k3s-agent.service`.
- Runtime: `containerd://2.3.4-k3s1.36`.
- Immutable image available on both nodes:
  `bedrock.local/nq@sha256:c57aa0eca562425a8038e323d968af206f4d2eae6eec112d4c126cea56dce33d`.
- No Docker container, Kubernetes workload container, or application PID is a
  current deployment contract.

## Expected state

Through B4, expected existence means two Ready nodes, the campaign namespace
and token-less service account, three Bound retained PVCs, digest-addressed
image availability, and zero workloads. B5 will change this only after exact
AG/NQ authorization.

Intentionally not asserted:

- Node Ready does not mean the NQ application is correct.
- API `/readyz` does not establish BEDROCK qualification.
- Bound PVC does not establish correct result custody.
- A future Pod Ready state will not establish semantic correctness.
- Existence of a future Service will not establish the desired effect.

## Candidate read-only Kubernetes facts

No monitor RBAC was installed. Before a workload exists, the smallest
descriptive candidate is `get,list,watch` on Nodes, Namespace,
PersistentVolumes, StorageClass, ServiceAccount, and PersistentVolumeClaims in
their applicable scopes. The workload-specific candidate for Pods, a selected
controller kind, Services, EndpointSlices, and Endpoints must be derived from
the actual B5 objects. No wildcard verb/resource, Secret read, exec, attach,
port-forward, or mutation verb is proposed.
