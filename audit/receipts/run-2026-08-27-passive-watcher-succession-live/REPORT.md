# Passive watcher succession + finite H live qualification receipt

Classification: **FINITE DELEGATED PASSIVE RENEWAL AND TRANSACTIONAL ACTIVATION QUALIFIED — OFFICE DORMANT**

Date: 2026-08-27 UTC  
Host: `sp00ky.net`  
Branch: `campaign/passive-watcher-succession-v1`  
Qualified code HEAD: `63078116295f966820a3c60a7198f2ae612ab406`

## Installed custody

* release: `/opt/nq-ng/passive-succession-6307811-musl`
* `nq` SHA-256: `2917ade7eead35d9c2f42fc0abc85bda42083788d428273278aaa279ae319534`
* recurrence unit: `/etc/systemd/system/nq-recurring-office.service`
* recurrence unit SHA-256: `5a8a9681b2240d43ed5c257dc6dbfc22187115b3e7712770999d2db7699c85a4`
* active NQ configuration SHA-256: `130a9264b2b0003c39c18cbd7e990f76375a4466b19c30c5a35a14e2c016737f`

The checked-in `live-inputs/` are non-secret specifications and static service
artifacts used during the bounded tranches. Private signing material was not
copied into repository custody.

## Final successful live tranche

* H4: `sha256:a115154f5e3f3494019bf445fe09943fc2f142981b04fb37de468990cef70d56`
* H4 standing: retired; 2/2 G, 2/2 E, and 1/1 succession edge issued
* aggregate H authority: 80 samples and 20 acquisitions; no remaining issuance
* G13: `sha256:e9cffc808aebf4348c04d6d5c6e4cecbe9d5ccac9cf246dd2e0bd42fabfa8761`
* G14: `sha256:7ff8bbf0983599832ca106bd8f781c698f66ed3b78875ccd63d16f137007206c`
* predecessor watcher digest: `sha256:041e1ec688c2af0c95028ec5bca1898df07b33617bec7c91920faf6f57aa425c`
* successor watcher digest: `sha256:49d1ccc67622545c03c287d9609a5fbf96795a29df0b67f4cc1f8ab7b5f71bc2`
* succession relation: `sha256:eeda35cfbab482852ca79e261d9a79a1c2de929cc3ac64b3316335113f680d7b`
* G13 admission: `076c2752-f713-4201-b6ac-e9f5938c2276`
* G14 fresh successor admission: `5cd8c636-6de5-4d53-8594-f41590efd33c`
* G13 genesis artifact: `sha256:cf5251885108475644dfd165e17f45802515accd70ef3f33114787ba9cbae6b6`
* G14 genesis artifact: `sha256:605603a4da87c3c9130b94af7079a49155606790323b54c9813b59753e37928e`
* E13: `sha256:78641dba42a9c5be2d2bd7b82c26b8ff503b43c717390deb99c7a4c46e45bcab`
* E14: `sha256:b186eaed5dfaf2c7d35e61c34b7124a0ad8c5d1ba1ccec1a3066d2dadd688ff0`
* final activation: `sha256:86d1e801e095c10ef0db94ccc5667b8f43e4707e7f1894f205a6e15b4c010e6e`
* H4 retirement event: `sha256:6e74788ff4df01827b910de7861562be258656c7b512dee561ab2998a0920719`
* E14 standing: revoked

## Required witnesses

While the E13 timer was mechanically enabled and the office remained staging,
two independent service wakeups each returned `outcome = inert` and
`attempts_consumed = 0`. E13 stayed at zero occurrences, ten remaining, and no
highest slot. After exact readiness validation and the durable armed event, the
same service path exposed ordinary finite recurrence behavior.

The live renewal was:

```text
G13
  → exact directed relation issued by H4
  → distinct G14 watcher
  → fresh admission through admit-successor
  → fresh G14 genesis
  → E14 issued by H4
```

No relation treated the two watchers as equal. The relation created no sample,
admission, recurrence authority, acquisition, diagnostic artifact, or
Nightshift cycle.

H4 reached all child-issuance ceilings. A deterministic and live defect was
then found: issuance exhaustion had been incorrectly treated as revocation of
already issued children. The repaired law distinguishes child issuance from
issued-child runtime. Release `6307811` revalidated and armed G14/E14 under the
exhausted-but-not-yet-retired H4 without permitting another child issuance.

Real armed ticks reached the ordinary recurrence boundary. They returned the
outer fail-closed error that substrate-origin collection produced no diagnostic
artifact. Subsequent exact status archaeology identified the inner cause:
G13/G14 active admission materializations had been created by a root shell as
mode-`0600` `root:root`, while the recurrence service correctly runs as `nq`.
The engine recorded a pre-provider admission-materialization refusal; no
provider invocation or `outcome_unknown` state occurred.

The deployment repair changed only file custody to mode `0600` `nq:nq` for the
four configured passive-succession admission files. SHA-256 before and after
was identical:

* G7: `64b9042e96548becace6b86fb040d600139ef67eed47d093e46a640fd219d847`
* G11: `552eeb47fa4bc07fe12f3e858f2f4dc7e23f4960ab94857f4c5784dc9e93d73d`
* G13: `0ddfa510ef6619b9d578820202f2127f1f1fc4c575f9022819874cdafab7dab8`
* G14: `ca5597188ea8818923102604fc951875a0467253f4180b7b3c0f8c0bd4142340`

A transient doctor run with the exact recurrence service principal,
supplementary groups, and bounded capabilities then verified G7, G11, G13,
and G14 admissions healthy. Missing admissions for discarded intermediate
G8/G9/G10/G12 configurations remain explicit historical staging refusals;
they confer no authority. Future successor admission must use the documented
capability-bounded `nq:nq` maintenance unit rather than a root shell.

The dormant configuration was then narrowed to the current G14 passive watcher
plus the unrelated pre-existing watchers; discarded G8/G9/G10/G12 staging
watchers are no longer active configuration entries. The canonical semantic
configuration digest is
`sha256:003bfeba665361f664abfccadfd6b6effdc84a4a33166f75123dcd4aa5f3f29f`;
the exact installed TOML SHA-256 is
`130a9264b2b0003c39c18cbd7e990f76375a4466b19c30c5a35a14e2c016737f`.
A second custody defect was exposed by that operation: atomic config
activation replaced an existing service-readable file with the temporary
file's root-only ownership. The repaired activation path preserves the exact
existing regular file's owner, group, and mode while still installing only the
validated byte snapshot. The live file was restored to `root:nq` mode `0640`
without changing its bytes. An exact service-principal doctor over the narrowed
configuration reports every configured watcher, including G14, healthy.

The observer produced 39 G13 samples (97,124 bytes) and 14 G14 samples (38,604
bytes). Retain-all remains comfortably inside the reviewed 24-hour horizon;
final free space was 27,244,380,160 bytes.

## Closeout

The final activation is `closed`; H4 is retired; G14 is closed; E14 is revoked.
The observer is inactive. The recurrence service is inactive. The recurrence
timer is disabled and inactive. No prepared child can self-activate.

A4 was inspected before and after. It remains exactly:

```text
diagnostic outcome: unknown
provider activity: unknown
coordination domain: linode:labelwatch-host
coordination: fenced
fencing epoch: 1
acquisition: recurrence:d555a10d2b4f11e7c6d550f43a6fd6d07631573bec5c14b54d09ca6b8e04beea
```

No Nightshift cycle or support evidence was created. The old one-shot provider
boundary was not selected or reused.

The next action is a separate human decision: authorize one unattended reviewed
24-hour H using 15-second sampling, five-minute acquisitions, four exact
six-hour G children, four exact six-hour E children, and three closed succession
edges. Qualification did not activate that charter.
