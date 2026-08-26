# Passive operational-continuity deployment supplement

Recorded: 2026-08-26T20:45:19Z

Classification: **CONTINUOUS PASSIVE DIAGNOSTIC OPERATION QUALIFIED THROUGH BOUNDED RENEWABLE GRANTS — LIVE OFFICE DORMANT**

This receipt appends to the passive load-sampling and recurring-office receipts.
It does not rewrite earlier custody, create Nightshift cadence, or reconcile the
historical one-shot-helper occurrence A4.

## Repository and release custody

- repository: `nq-ng`
- branch: `campaign/passive-operational-continuity`
- starting commit: `b001c5e14f2a5d42e2ac164ada9fb7dde85960ef`
- qualified source commit: `b697df715fb6088aaa7de63e52fd2061804849b8`
- private static release archive SHA-256:
  `b86ea4d41fa3f96979ef00a5200998790412550efa58df2f857da32d5738450e`
- private static Debian package SHA-256:
  `4d3d9e1dd0ee3fc8de1c8909b8b68bc8effca5a0447b5c1ddcd5d177a247d5eb`
- installed tree: `/opt/nq-ng/passive-operational-continuity-b697df7-musl`
- installed NQ SHA-256:
  `9d1a3d6f31988c91c692c086a966ee053a5a69efaec1c7547e34762a7099f7d2`
- installed passive helper SHA-256:
  `77e2085acdb3e39f42fe53e8288c0fc3c390b736fe97db6aa3a529ffdbb740a0`

The first uploaded GNU build required a newer glibc than the target and was
never used for production evidence. The installed musl build passed the exact
production preflight.

## Authority model

The implementation enforces three independent clocks and two independently
finite grants:

```text
observer generation G  -> sampling slots and immutable raw samples
recurrence enrollment E -> diagnostic acquisition slots and occurrences
Nightshift               -> independently governed reasoning cycles
```

Sampling cannot mint an NQ acquisition, an NQ acquisition cannot sample or
renew an observer generation, and neither creates a Nightshift cycle. Continuous
operation means explicit succession of finite G and E grants, not an infinite
grant.

Protocol invariants include immutable samples and occurrences, exact sample
binding, replay without resampling, no old-helper fallback, one sample per
sampling slot, one writer per generation, exact capacity/vantage enforcement,
no referenced-sample deletion, no mutable `latest` authority, no recursive
renewal, and no reinterpretation of history by policy changes.

Deployment policy constrains allowed intervals, finite duration/count, store
bytes, free disk, eligibility age, key windows, restart/startup mode, and drift
handling. Each immutable observer generation and recurrence enrollment selects
inside that envelope.

## Deployment policy and observer generations

- active operational policy schema: `nq.passive_load_operational_policy.v1`
- active policy ID:
  `sha256:7b676712e141b4aacfb276af7227f80e892eb902e191aedee384dee7f652bf34`
- active policy file SHA-256:
  `1511436038f5e9bb5e86c8fc1a9b8ec62afecaef135ad236d6da2867c0b96784`
- observer-generation schema:
  `nq.passive_load_observer_generation.v1`
- sampling-slot schema: `nq.passive_load_sampling_slot.v1`
- sample interval used in the live grants: 5 seconds
- sample eligibility maximum age: 30 seconds
- store mode: finite `retain_all`; no archive deletion path
- storage guards: generation byte bounds plus 10 GiB required free space
- exact systemd capacity-context ID:
  `sha256:6c6e34b0e088655fce62d4dd15ea355e6d79015736c6e0fb5b8219feac492c7d`

Qualified generation chain:

| Generation | Key | Samples | Final state | Store bytes |
| --- | --- | ---: | --- | ---: |
| `sha256:4c377d933800c089419a0ded9843165eba2f54ff505726b9482418d3c0f6afe1` | K1 | 24 | exhausted | 58,686 |
| `sha256:aaf390773cd0ddef83603e80191ba1c1d64eae2d4b78a3152e215650f0b2ba8d` | K2 | 40 | exhausted | 107,355 |
| `sha256:4c7c3bbcecfd94380e9dedfd24446741ae7ed2cb1e651971681430efe07d75b5` | K2 | 97 | expired | 238,552 |
| `sha256:e3dfe6acf98cc844dccbec2da31ff2def875b4756490968d262b1fbda8f4ac10` | K2 | 55 | explicitly retired | 138,026 |

Each successor named its exact predecessor. Renewal preserved all historical
sample identities and gaps. G4 retirement event:
`sha256:35d92c6a74fa93d547f98083a83bbcf0fb91548aa28723c2ba5b51fa4e60d21b`.
A post-retirement service invocation emitted no sample.

The active selection stores contain one generation metadata JSON file in
addition to the sample counts above. No referenced sample was deleted or
archived.

## Signing-key lifecycle

- issuer: `nq-passive-load-observer:labelwatch-host-operational-continuity`
- K1 ID: `passive-load-operational-20260826-g1`
- K1 public-key digest:
  `sha256:ba50a467f1e42fef20f1477e9f300247197d4de6ac960b405a38fecdbf93fe34`
- K2 ID: `passive-load-operational-20260826-g2`
- K2 public-key digest:
  `sha256:6193222f1949cd2d55eb30410623f6bf7dbe325aa561e3eb50e76026daadd86d`

K1 and K2 are software-held Ed25519 keys, not hardware-bound or
non-exportable. Key authority is generation-bounded: K1 historical samples
remain verifiable, while new K2 generations use K2. Rotation did not rewrite
sample semantics or history and created no indefinite dual-signing authority.
No private key material is recorded here.

## Independent recurrence renewal witness

The exact G4 watcher/admission was:

- watcher: `labelwatch-host-passive-continuity-g4`
- governed subject: `host:labelwatch-host`
- admission occurrence: `443ea80e-f12a-4a9b-b2ba-e43d38434c30`
- admission binding digest:
  `sha256:00c06e199f5031ad224397da7db00d5a35ed0748f46097a9d8d67fcbce90360b`
- watcher semantic digest:
  `sha256:d7c3a957546138585463aa06cca95dbb6125f72038d430969e9fcfece0c92835`
- recurrence policy ID:
  `sha256:95318eafd231e0a161ba725be236a93d6604195cd1baac4813678495efdbcf82`
- coordination domain:
  `passive-load-generation:sha256:e3dfe6acf98cc844dccbec2da31ff2def875b4756490968d262b1fbda8f4ac10`

G4 genesis used an exact pre-existing sample and persisted artifact
`sha256:dc1d5011621d6b248044fa65fba1420e164b163d302ea3c04c35e9f4871f7bb8`.
Sampling remained independent of this diagnostic occurrence.

E1 was an exact one-occurrence grant:

- enrollment:
  `sha256:284157f2188b8a967e4afe73a69513e9b01532cd65617cb54b03a7ce0a014f63`
- acquisition:
  `recurrence:f8d7df26e27acd309d926be7d54f3fc86ef16d080702f8e3ce944d70b4fb00a2`
- slot index / scheduled time: `1` / `1787776500000`
- fencing epoch: 1
- origin intent:
  `sha256:37bb910643874df246803c90d93a332460cc818257a510ed977df0a49a9dea07`
- origin attestation digest:
  `sha256:aab5883c313fa5bd09fffe2b635c904a68f890cbb804a2ae53a767cdf9a1aadb`
- provider intake acknowledgment: `b50c2c56-84cf-4d68-9b0d-2283c142c4de`
- intake digest:
  `sha256:a3b794bd4addd202f30e605c77f888a85919668ac6710722ddf58802fc93388d`
- run: `f309b615-fa43-44c2-ab48-3061ed8ecb15`
- artifact:
  `sha256:c4b4fc2d19d0cfa8a5f1d715ab45c82e712ebc790241d7eea3782add47b9390a`

E2 was a separate exact one-occurrence grant:

- enrollment:
  `sha256:9302cf14924e0d1cd1cb245d70661e2be9862d58d06edcb82aeca267fcdb7445`
- acquisition:
  `recurrence:1b89d0844ff0bb5b2978362a215240e2a6b5fccc57ef2704627c2eb6d904813a`
- slot index / scheduled time: `1` / `1787776590000`
- fencing epoch: 2
- origin intent:
  `sha256:711d367ed146e2395b254132c157ae8e7afb81f8745622d83c84d3398149b920`
- origin attestation digest:
  `sha256:9d8e0e88f803f360b08d3b33ccc8843f5c7d1fc46ddccee2e7d3a3c21c6f7c65`
- provider intake acknowledgment: `dee55c60-ec8d-43b8-92e8-8f9777872e28`
- intake digest:
  `sha256:76f79f025285ebaf9d3fb23f417d0b82d476abf8cbf485fa7201677f8b3c3bdf`
- run: `de96d3f1-55be-4284-9693-66c4e3b48c99`
- artifact:
  `sha256:3d9df6085db62e5016461da84f96eedeebafe2106f4554e3a67fa740cdbcd039`

Both conclusions were `explicitly_absent`. Exact replay retained each artifact
and created no sample. E2 first encountered a pre-provider backoff and later
completed as the same occurrence; cadence and authority did not drift. After
E2 exhaustion, another service invocation returned `enrollment_unavailable`
and created neither a sample nor an acquisition. Renewing G did not create E;
renewing E did not create G.

## Failure, restart, gaps, and storage

The live and deterministic campaigns established:

- an observer started under a mismatched capacity context failed closed with
  zero samples;
- capacity/vantage/configuration drift pauses the exact generation and requires
  a new reviewed generation;
- process restart recovers persisted generation facts, creates no missed sample,
  and cannot reopen exhausted/retired authority;
- missing sampling slots remain gaps; NQ uses only an exact eligible sample or
  refuses/waits without old-helper fallback;
- partial or failed sample persistence never becomes selectable;
- policy broadening did not enlarge G1; tightening/refusal applies only to
  future acts without rewriting old facts;
- active-store and required-free-space guards fail before opportunistic history
  deletion.

The measured bounded stores average approximately 1,282 bytes per signed sample
before filesystem/generation overhead. At a five-second sampling interval, the
observed total-store rate projects to roughly 1.8 MiB/hour, 43 MiB/day,
300 MiB/week, or 1.3 GiB per 31-day month. These projections choose bounded
grant/storage limits; they are not evidence of indefinite safety. Final free
space was 27,628,933,120 bytes.

Archive machinery was not earned for this V1 campaign. Finite `retain_all`
generations and the hard 10 GiB free-space guard bounded the qualified live
window. Longer operation requires explicit grants and, before those bounds make
it necessary, a separate immutable archive-custody qualification.

## Installed identities and close state

- observer unit SHA-256:
  `4679313509d9a184bdce9a35cfc7e125cb8653229423883814fe064b271d7d49`
- recurring one-shot unit SHA-256:
  `0c05ea4554ba70d3ab487a7a7a5e2e83a81703c480067520e0d1c9666a916192`
- dormant timer SHA-256:
  `596ed31fe6f04724df7cd44044bb756c3830386494ffeb46f1a076d6d22f6752`
- G4 generation file SHA-256:
  `e3dfe6acf98cc844dccbec2da31ff2def875b4756490968d262b1fbda8f4ac10`
- G4 provider file SHA-256:
  `98f7a54bc430c0ceaa51a33eb8f33fe2d2282120a69532a1ec2c3235f99158e9`
- recurrence policy file SHA-256:
  `20237fa16da459670492f6a7915d51e5b2cb626b1045709ce7f7eb16ee278917`
- E1 file SHA-256:
  `cb6dfa41977be2f332d4e55f58c6b333ecfbd7582d5c471d24e2653ed4f6aa35`
- E2 file SHA-256:
  `84f0ef548c7041fc57dd069d56495ca043ab20445e7382ce0fe9584fb739325f`
- E2 selector environment SHA-256:
  `e921086fba4eb27a2c0166eff36bdd6d234e9b6675411c24a3670576266ce067`
- NQ config SHA-256:
  `1ed868e6fe9bbb1a687edb3df17edd7f5d615c926471b702e5ff125ecc6705b8`
- final NQ database SHA-256:
  `5d1501abdb51daaa938e1c378482e19317554283c15562410f40ecbd4fa4c098`

At close:

- `nq-passive-load-observer.service`: static and inactive
- `nq-recurring-office.service`: static and inactive
- `nq-recurring-office.timer`: disabled and inactive
- `nqd.service`: inactive
- no Nightshift cycle was created
- no automatic renewal or uncontrolled recurrence was enabled

## A4 remains untouched

- A4:
  `recurrence:d555a10d2b4f11e7c6d550f43a6fd6d07631573bec5c14b54d09ca6b8e04beea`
- old domain: `linode:labelwatch-host`
- epoch: 1
- diagnostic outcome: unknown
- provider activity: unknown
- coordination: fenced
- holder: A4
- old enrollment: revoked
- A5: not created

The passive boundary neither reuses nor releases the old one-shot-helper domain.

## Validation standing and limits

- operational lifecycle, deterministic clock, key rotation, drift, restart,
  retention/reference, storage, hostile policy, and process-boundary tests:
  passed
- release catalog/manifest/protocol/package verifiers and structural guard:
  passed
- formatting, Clippy with warnings denied, and `git diff --check`: passed
- Nightshift full regression and no-actuation checks: passed with Nightshift
  untouched
- full NQ workspace targets passed in partitioned/serial runs; aggregate
  high-parallel runs exposed only known environment scheduling/EPERM effects,
  and every affected test passed unchanged in its appropriate rerun
- strict-host-key live verification matched hashes, exact E1/E2 custody, dormant
  services, disk guards, and the unchanged A4 fence

This qualifies continuous passive diagnostic operation through explicit bounded
renewable grants. It does not qualify automatic renewal, infinite retention,
zero observer effect, hardware-bound keys, coherent backup/restore, physical
  host identity, physical power-loss behavior, or recurring Nightshift reasoning.
