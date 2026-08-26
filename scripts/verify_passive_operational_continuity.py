#!/usr/bin/env python3
"""Fail closed if passive operational continuity regains ambient authority."""

from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
operational = (root / "crates/nq-passive-load-helper/src/operational.rs").read_text()
production = operational[: operational.index("#[cfg(test)]")]
main = (root / "crates/nq-passive-load-helper/src/main.rs").read_text()
recurrence = (root / "crates/nq-store/src/recurrence.rs").read_text()
unit = (root / "packaging/systemd/nq-passive-load-observer.service").read_text()
doctrine = (root / "docs/PASSIVE_LOAD_OPERATIONAL_CONTINUITY_V1.md").read_text()

failures: list[str] = []

required_protocol = (
    "nq.passive_load_operational_policy.v1",
    "nq.passive_load_observer_generation_spec.v1",
    "nq.passive_load_observer_generation.v1",
    "nq.passive_load_sampling_slot.v1",
    "max_generation_samples",
    "expires_at_unix_ms",
    "WaitForNextSampleSlot",
    "SampleCurrentSlot",
    "one sample occupies one deterministic sampling slot",
    "available_parallelism capacity/vantage context drifted",
    "hard active-store byte bound would be exceeded",
    "required free-space guard refuses sampling",
    "SigningKeyRevoked",
    "OperatorRetired",
)
for required in required_protocol:
    if required not in production:
        failures.append(f"operational state machine lacks {required}")

for forbidden in (
    "remove_file(",
    "remove_dir",
    "rename(",
    "std::process::Command",
    "nightshift::",
    "nq_store::",
    "CronExpression",
    "PagerDuty",
    "AlertManager",
):
    if forbidden in production.lower() if forbidden == "nightshift::" else forbidden in production:
        failures.append(f"operational producer contains forbidden surface {forbidden}")

required_cli = (
    "PrepareGeneration",
    "ObserveGeneration",
    "SampleOnceGeneration",
    "GenerationStatus",
    "RetireGeneration",
    "RevokeGenerationKey",
)
for required in required_cli:
    if required not in main:
        failures.append(f"CLI lacks bounded generation command {required}")

if "observe-generation" not in unit:
    failures.append("systemd observer does not require an immutable generation")
if "Restart=on-failure" not in unit or "Restart=always" in unit:
    failures.append("systemd restart policy is not bounded failure recovery")
if any(line.strip() == "[Install]" for line in unit.splitlines()):
    failures.append("observer unit must remain static and explicitly started")
for forbidden in ("OnCalendar=", "OnUnitActiveSec=", "sample-once", "recurring tick"):
    if forbidden in unit:
        failures.append(f"observer service regained cadence/diagnostic authority through {forbidden}")

if any(
    token in recurrence
    for token in ("observe-generation", "sample-once-generation", "prepare-generation")
):
    failures.append("NQ recurrence can create or invoke sampling generations")

required_doctrine = (
    "Continuous operation is a sequence of bounded grants, not an unbounded grant.",
    "Sampling creates observations, not diagnostic occurrences.",
    "Diagnostic recurrence consumes observations, not sampling authority.",
    "Nightshift reasoning remains an independent clock.",
    "There is no automatic successor generation or recurrence enrollment.",
    "A4 remains",
)
normalized_doctrine = " ".join(doctrine.replace("> ", "").split())
for required in required_doctrine:
    if required not in normalized_doctrine:
        failures.append(f"continuity doctrine lacks required law: {required}")

if failures:
    for failure in failures:
        print(f"passive-operational-continuity: {failure}", file=sys.stderr)
    raise SystemExit(1)

print("passive-operational-continuity: finite renewable authority surface qualified")
