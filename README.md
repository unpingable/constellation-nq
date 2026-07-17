# NQ-ng

NQ-ng is a local-first operational evidence service. It runs independently
scheduled witness helpers, validates their output against compiled and
versioned profiles, retains both accepted evidence and rejected custody
artifacts, and evaluates compiled detectors without granting helpers any
authority over findings or actions.

The governing rule is:

> Mechanically open integrations, compiled and versioned semantics.

This repository is a greenfield successor. Legacy NQ bytes may be referenced
at cutover, but legacy verdicts are never imported as current state.

The current developer preview contains the protocol/SDK and executable hostile
corpus, explicit profile registry, generic SQLite evidence substrate, bounded
stdio and authenticated persistent-Unix helper supervisors, admission locks,
detector lifecycle, daemon-local API/console, complete operator CLI, a native
host helper, a Python wire-compatible specimen, and a bounded Rust compiler
for authority-free system cuts and consumer-specific projections. The cut
contract is not yet wired into daemon storage, NQ evaluation, Porter, NetBox,
or AG. See
[docs/PLAN.md](docs/PLAN.md) for the governing roadmap,
[docs/PORTER_NETBOX_ADDENDUM.md](docs/PORTER_NETBOX_ADDENDUM.md) for the
Porter/QEMU/NetBox system-cut contract and later integration specimens,
[docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) for the exact
developer-preview boundary, and
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for verification commands.
