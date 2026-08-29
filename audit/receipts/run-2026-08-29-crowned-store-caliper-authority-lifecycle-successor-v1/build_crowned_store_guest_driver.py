#!/usr/bin/env python3
"""Derive CROWNED-STORE's fresh VM driver from the sealed CALIPER fixture.

CALIPER remains terminal.  This constructor verifies the exact generated
CALIPER driver, replaces every campaign-owned identity and mutable pathname,
and changes only the resolved generation-store mode assertion.  It never
reads or reuses the predecessor VM overlay, key, or authority state.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CALIPER_BUILDER = ROOT / (
    "audit/receipts/run-2026-08-29-caliper-c3-vm-authority-lifecycle/"
    "build_caliper_guest_driver.py"
)
EXPECTED_CALIPER_DRIVER_SHA256 = (
    "e272949034139e9f587bca7ae4927bc9d27a803a84b8639a96801bd152b59966"
)
OUTPUT = Path(sys.argv[1]) if len(sys.argv) == 2 else None


def replace_exact(document: str, old: str, new: str) -> str:
    count = document.count(old)
    if count == 0:
        raise RuntimeError(f"required CALIPER fixture text absent: {old!r}")
    return document.replace(old, new)


def main() -> None:
    if OUTPUT is None or not OUTPUT.is_absolute():
        raise RuntimeError("usage: build_crowned_store_guest_driver.py ABSOLUTE_OUTPUT")

    with tempfile.TemporaryDirectory(prefix="crowned-store-driver-") as temporary:
        caliper_driver = Path(temporary) / "caliper-driver.py"
        subprocess.run(
            [sys.executable, str(CALIPER_BUILDER), str(caliper_driver)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        source_bytes = caliper_driver.read_bytes()

    observed = hashlib.sha256(source_bytes).hexdigest()
    if observed != EXPECTED_CALIPER_DRIVER_SHA256:
        raise RuntimeError(f"generated CALIPER driver custody changed: {observed}")

    document = source_bytes.decode()
    document = replace_exact(
        document,
        "passive-vm-release-reproducibility-and-lifecycle-v1-c3",
        "crowned-store-authority-lifecycle-successor-v1",
    )
    document = replace_exact(document, "caliper-nq-ng.deb", "crowned-store-nq-ng.deb")
    document = replace_exact(document, "7690816a1e574e32eb6606619bbed980ee3e6ea2469a745d685b065693c6566d", "dfb8e57c6decb87647f66f1f89d0126f215541701c60143dc1166128b82e35d1")
    document = replace_exact(document, "e06a7b85699d23bbc0637fd4a1288f8c15afcbc8", "a56342762a8b46f4c01b5885c7d7c5728ab27a60")
    document = replace_exact(document, "CALIPER", "CROWNED-STORE")
    document = replace_exact(document, "caliper", "crowned-store")
    document = replace_exact(document, 'INSTANCE_ID = "8451902"', 'INSTANCE_ID = "8452903"')
    document = replace_exact(
        document,
        'if readiness.get("mode") != 0o750 or readiness.get("owner_uid") != expected_uid or readiness.get("owner_gid") != expected_gid:',
        'if readiness.get("mode") not in {0o750, 0o2750} or readiness.get("owner_uid") != expected_uid or readiness.get("owner_gid") != expected_gid:',
    )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(document)
    OUTPUT.chmod(0o755)
    print(hashlib.sha256(document.encode()).hexdigest())


if __name__ == "__main__":
    main()
