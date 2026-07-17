# Local preflight record

Date: 2026-07-17 (America/New_York)

The static harness test passed. A separate `--preflight-only` invocation used
the existing `dist/nq-ng_0.1.0_amd64.deb` with SHA-256
`a0dd810164f36aeef82ab6d4cc16dff00d1544e6176c769222d71fbab1cbe836`
and an intentionally absent cloud-image path. It exited 1 and persisted this
exact refusal:

```text
result=refused
step=input-custody
reason=Ubuntu cloud image is not a regular non-symlink file: /tmp/ubuntu-24.04-cloud-image-not-present.qcow2
```

The run also recorded the configured 8 GiB scratch cap (`8589934592` bytes)
and 12 GiB free-space stop (`12582912` KiB) before refusing. No overlay, seed,
guest, package lifecycle, cross-UID transition, or AF_UNIX exchange was run.
This is refusal evidence only.

That preserved top-level Debian artifact predates the installed-manifest
startup gate. It is adequate for this preflight's input-custody refusal but is
not an eligible artifact for the current full lifecycle harness.
