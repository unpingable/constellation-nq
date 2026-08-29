#!/usr/bin/env python3
"""Derive CALIPER's fresh VM driver from the preserved SOCKETWRENCH fixture.

The predecessor fixture is test logic only.  Its exact bytes are verified, all
campaign and deployment identities are replaced, and the qualified
pre-authority generation-store construction/readiness law is inserted.  No
predecessor authority object or mutable VM state is consumed.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "audit/receipts/run-2026-08-28-passive-vm-lifecycle-repair-v1-s2-basic-lifecycle/guest-passive-qualification.py"
EXPECTED_SOURCE_SHA256 = "4fec0940eb42482df6baab1f00ee5016c98ef1379caf076fdf96a70ea57305ab"
OUTPUT = Path(sys.argv[1]) if len(sys.argv) == 2 else None


def replace_exact(document: str, old: str, new: str) -> str:
    if old not in document:
        raise RuntimeError(f"required predecessor fixture text absent: {old!r}")
    return document.replace(old, new)


def main() -> None:
    if OUTPUT is None or not OUTPUT.is_absolute():
        raise RuntimeError("usage: build_caliper_guest_driver.py ABSOLUTE_OUTPUT")
    source_bytes = SOURCE.read_bytes()
    observed = hashlib.sha256(source_bytes).hexdigest()
    if observed != EXPECTED_SOURCE_SHA256:
        raise RuntimeError(f"predecessor driver custody changed: {observed}")

    document = source_bytes.decode()
    replacements = [
        ("SOCKETWRENCH", "CALIPER"),
        (
            "passive-vm-lifecycle-repair-v1-s2-final",
            "passive-vm-release-reproducibility-and-lifecycle-v1-c3",
        ),
        ("20260828", "20260829"),
        ("socketwrench-nq-ng.deb", "caliper-nq-ng.deb"),
        (
            "821c8f7f5dc536c46222c514f9d3b0114efd23a9045bf946d1eb76cd0ddcf0a8",
            "7690816a1e574e32eb6606619bbed980ee3e6ea2469a745d685b065693c6566d",
        ),
        (
            "4e109f889330b876e7c1776b27fcde697ef77f21",
            "e06a7b85699d23bbc0637fd4a1288f8c15afcbc8",
        ),
        ('INSTANCE_ID = "9382051"', 'INSTANCE_ID = "8451902"'),
        (
            '"classification": "PASSIVE-VM-DEPLOYMENT-AND-RECOVERY-QUALIFIED"',
            '"classification": "PASSIVE-VM-AUTHORITY-LIFECYCLE-QUALIFIED"',
        ),
    ]
    for old, new in replacements:
        document = replace_exact(document, old, new)
    document = replace_exact(document, "socketwrench", "caliper")

    staging_marker = """    os.chown(STAGING, pwd.getpwnam(\"nq-passive-load-observer\").pw_uid,
             grp.getgrnam(\"nq-passive-load-reader\").gr_gid)

    key_result = run("""
    staging_replacement = """    os.chown(STAGING, pwd.getpwnam(\"nq-passive-load-observer\").pw_uid,
             grp.getgrnam(\"nq-passive-load-reader\").gr_gid)
    # Deployment/charter preparation owns the dedicated store roots.  Runtime
    # authority and sampling are not permitted to manufacture these paths.
    SAMPLES.mkdir(mode=0o750)
    os.chown(SAMPLES, pwd.getpwnam(\"nq-passive-load-observer\").pw_uid,
             grp.getgrnam(\"nq-passive-load-reader\").gr_gid)

    key_result = run("""
    document = replace_exact(document, staging_marker, staging_replacement)

    store_marker = """        store = SAMPLES / f"g{index}"
        spec = {
"""
    store_replacement = """        store = SAMPLES / f"g{index}"
        store.mkdir(mode=0o750)
        os.chown(store, pwd.getpwnam(\"nq-passive-load-observer\").pw_uid,
                 grp.getgrnam(\"nq-passive-load-reader\").gr_gid)
        spec = {
"""
    document = replace_exact(document, store_marker, store_replacement)

    generation_marker = """        generations.append({"id": generation_id, "path": str(generation_path), "store": str(store), "document": generation})
        previous_path, previous_id = generation_path, generation_id

    providers: list[dict[str, object]] = []
"""
    generation_replacement = """        generations.append({"id": generation_id, "path": str(generation_path), "store": str(store), "document": generation})
        readiness = parse_json(run_observer(
            f"pre-authority-g{index}-store-readiness",
            ["generation-store-readiness", str(generation_path)],
        ))
        expected_uid = pwd.getpwnam("nq-passive-load-observer").pw_uid
        expected_gid = grp.getgrnam("nq-passive-load-reader").gr_gid
        if readiness.get("mode") != 0o750 or readiness.get("owner_uid") != expected_uid or readiness.get("owner_gid") != expected_gid:
            raise RuntimeError(f"generation {index} store readiness identity/mode mismatch: {readiness}")
        if readiness.get("sample_store") != str(store):
            raise RuntimeError(f"generation {index} readiness named another store")
        previous_path, previous_id = generation_path, generation_id

    record("pre-authority-generation-store-readiness.json", {
        "stores": [json.loads((RESULTS / f"pre-authority-g{index}-store-readiness.stdout").read_text()) for index in [1, 2]],
        "authority_created": False,
    })

    providers: list[dict[str, object]] = []
"""
    document = replace_exact(document, generation_marker, generation_replacement)

    closeout_marker = """        run_nq("grant-retire", ["operating", "grant-retire", grant_id, "--operation-id", f"caliper-retire-h-{secrets.token_hex(8)}", "--reason", "bounded VM closeout", "--state-dir", str(OPERATING)])
        final_activation = parse_json("""
    closeout_replacement = """        run_nq("grant-retire", ["operating", "grant-retire", grant_id, "--operation-id", f"caliper-retire-h-{secrets.token_hex(8)}", "--reason", "bounded VM closeout", "--state-dir", str(OPERATING)])
        revoked_key = RESULTS / "revoked-generation-signing-key"
        key_digest = sha_file(KEY)
        shutil.move(KEY, revoked_key)
        os.chmod(revoked_key, 0o000)
        record("revoked-key-custody.json", {"live_path_present": KEY.exists(), "sha256": key_digest, "preserved_path": str(revoked_key), "mode": "000"})
        final_activation = parse_json("""
    document = replace_exact(document, closeout_marker, closeout_replacement)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(document)
    OUTPUT.chmod(0o755)
    print(hashlib.sha256(document.encode()).hexdigest())


if __name__ == "__main__":
    main()
