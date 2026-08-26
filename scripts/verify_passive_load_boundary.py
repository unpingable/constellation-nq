#!/usr/bin/env python3
"""Fail closed when the passive load boundary regains forbidden authority."""

from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
helper = (root / "crates/nq-passive-load-helper/src/lib.rs").read_text()
engine = (root / "crates/nq-core/src/engine.rs").read_text()
config = (root / "crates/nq-core/src/config.rs").read_text()
unit = (root / "packaging/systemd/nq-passive-load-observer.service").read_text()
doctrine = (root / "docs/PASSIVE_LOAD_SAMPLING_V1.md").read_text()

failures: list[str] = []

serve = helper[helper.index("pub fn serve(") : helper.index("fn build_report(")]
for forbidden in ("load_1m_token()?", "available_parallelism()?", "sample_once(", "observe("):
    if forbidden in serve:
        failures.append(f"provider retrieval path contains forbidden sampling call {forbidden}")

production = helper[: helper.index("#[cfg(test)]")]
for forbidden in ("pressure_present", "current = true", "nq-host-helper"):
    if forbidden in production:
        failures.append(f"passive producer/provider contains forbidden semantic shortcut {forbidden}")

required_engine = (
    "validate_diagnostic_source_timing",
    "ordinary diagnostic acquisition cannot consume passive sample custody",
    "passive sample is future, stale, or was not fixed before provider launch",
    "passive sample signature is not authentic",
)
for required in required_engine:
    if required not in engine:
        failures.append(f"engine lacks passive timing/authenticity invariant {required}")

required_config = (
    "nq.passive_host_load_provider_config.v1",
    "passive_host_load_sample",
    "nq.host/v1 300000ms reliance horizon",
)
for required in required_config:
    if required not in config:
        failures.append(f"configuration lacks closed passive policy invariant {required}")

for forbidden in ("CPUQuota=", "CPUAffinity=", "AllowedCPUs=", "Restart=always"):
    if forbidden in unit:
        failures.append(f"observer unit changes capacity/restart semantics through {forbidden}")
if any(line.strip() == "[Install]" for line in unit.splitlines()):
    failures.append("observer unit must remain static and explicitly started")
if "PrivateNetwork=yes" not in unit or "Restart=on-failure" not in unit:
    failures.append("observer unit lacks closed network/restart behavior")
if "observe-generation" not in unit or "passive-load-observer.toml" in unit:
    failures.append("observer unit does not require an exact finite generation")

required_doctrine = (
    "Diagnostic acquisition may consume an observation. It need not cause the observation to occur.",
    "A stable observer can reduce occurrence-triggered perturbation. It does not make observation physically free.",
    "A4 belongs permanently to the old one-shot-helper provider boundary",
    "There is no mutable `latest` authority record.",
)
normalized_doctrine = " ".join(doctrine.replace("> ", "").split())
for required in required_doctrine:
    if required not in normalized_doctrine:
        failures.append(f"doctrine lacks required nonclaim/law: {required}")

if failures:
    for failure in failures:
        print(f"passive-load-boundary: {failure}", file=sys.stderr)
    raise SystemExit(1)

print("passive-load-boundary: qualified structural surface")
