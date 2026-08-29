# QUIET-EMBER retained OCI release-custody successor

Campaign: `QUIET-EMBER`

Slug: `release-custody-successor-v1`

Classification:
`QUALIFIED-SUCCESSOR-RETAINED-OCI-RELEASE-CUSTODY-V1`

This successor repairs only the release-custody refusal against the prior
QUIET-EMBER result. The prior result remains append-only evidence: its runtime
carrier and lifecycle boundaries passed, but its reported OCI specimen was not
retained or reproducible from content-pinned inputs. No prior classification
is rewritten.

This result grants no NQ, Docket, AG, Kubernetes, provider, deployment, or
production authority. It does not start BEDROCK B6 or OPEN-QUARRY.

## Lineage

* retained canonical NQ base:
  `7c361a9b43c6eb25645dcde5fa5222ae5a70ac28`;
* prior QUIET-EMBER implementation:
  `35a3cc9ea956d93697e3cfc73f7a7bd3733f415a`;
* prior refused result head:
  `f7cdf9e9c87faccb42cc6c0f9191b24be650a6d4`;
* successor release implementation and specimen source:
  `98419132b91619304351381f05dc2ca7a05c2167`;
* branch: `campaign/quiet-ember-release-custody-successor-v1`.

## Repaired custody law

`release/quiet-ember-oci-input-pins-v1.json` is a closed seven-object input
contract. It binds exact source, destination, installed mode, size, and SHA-256
for `nq`, `nq-passive-load-helper`, `nq-bedrock-runtime-carrier`, the dynamic
loader, `libc`, `libm`, and `libgcc_s`. The builder refuses a symbolic source,
unknown or missing input, changed size, or changed bytes before emitting an
admitted manifest.

The builder first copies each verified object to an immutable release input
bundle, rechecks that retained copy, and builds the rootfs only from those
retained bytes. OCI config, manifest, compressed layer, uncompressed diff ID,
index, layout, archive, exact input facts, sizes, toolchain provenance, and a
complete digest inventory are retained under `release/` in this receipt.

`scripts/verify-bedrock-oci-release.sh` is an offline, non-actuating verifier.
It refuses an unknown retained file or symlink, rechecks every manifest entry,
every copied input and mode, descriptor digest and size, layer diff ID, facts
cross-binding, archive digest and size, and exact archive-to-layout reopening.

## Exact retained specimen

* files retained: `18`;
* image reference:
  `bedrock.local/nq@sha256:94c82c5b69b94660918ad34be401217c42d9f4888489bd15f26b5f6ad306181a`;
* manifest: `sha256:94c82c5b69b94660918ad34be401217c42d9f4888489bd15f26b5f6ad306181a`, 408 bytes;
* config: `sha256:fac2c5e7fd1a282e4e6749a3eaa20a60abdff1fdd01bd0a09ab3af43d3267929`, 1273 bytes;
* layer: `sha256:0d8511437a524965a8f94d51a5822c196de8e7227d759a3b56ce81f1de43956d`, 11423603 bytes;
* layer diff ID:
  `sha256:b791c62a06866c09c19a80791037a9be923833ff8716c52b6e551aa9d95017ec`;
* archive: `sha256:fbf0378137ee1b2f8209169ff3e2ea32aaf8088111845623dea0ab8a3594774c`, 11438080 bytes;
* release digest manifest:
  `sha256:a2546401b8789a90968d360504787a534b55e2fffdc4b3aa068eb9df7afd7798`;
* input pins:
  `sha256:f092983089528e1fb3523bb7e3200529bca3963b427a0a83b507039cb95ecb8b`;
* NQ: `sha256:f926f9ef33bc24bb38f774950766e438373dd759364550e5efbc763a5ffa804f`;
* passive helper:
  `sha256:5aba0096fbe824d18a6e5ad646d414cb2b0fff1adba3687df3974acd0883aa98`;
* runtime carrier:
  `sha256:a102413a5db548b99cfedeac23cc4621477793ae45d7b80491fb66cada20cf77`.

## Qualification

The final release was built from exact clean commit `9841913...`. The offline
verifier passed against the generated release and again after repository
retention. A second build used only the retained `inputs/` tree plus the exact
source commit and was byte-identical across the entire release directory. A
same-size passive-helper content-mutation fixture refused before
`manifest-digest` existed and emitted empty stdout.

The unchanged runtime carrier focused suite passed 10 cases: nine library
cases and one real parent-death process case, zero failed. The full workspace
suite passed with zero failures. Strict Clippy with warnings denied,
formatting, shell syntax, JSON validation, and diff checks passed. ShellCheck
was unavailable on this host and is not claimed.

The OCI specimen was never loaded, pushed to a registry, scheduled, or run as
a container. Its default remains the qualified inert runtime carrier.

## Authority/effect accounting and teardown

AG proposals/spends/issuances, Docket attempts/settlements, NQ live prepared
occurrences/claims/fences/releases, mechanics invocations, Kubernetes
workloads/services/Pods, provider starts, VMs, listeners, live-route changes,
recurrence attempts, samples, and acquisitions: all zero.

The retained release bundle is the only campaign artifact. No process,
listener, VM, credential, secret, temporary artifact, or concealed teardown
obligation remains. GLASSHOPPER and all live routes were untouched.
