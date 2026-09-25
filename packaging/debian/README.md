# Debian package lifecycle

These files are inputs to `scripts/build-release-bundle.sh`; they are not a
claim that the repository is a conventional Debian source package.

The exact package inventory includes every helper that serves a cataloged
profile under `/usr/lib/nq/helpers/`: `nq-host-helper`,
`nq-host-resource-helper`, `nq-operator-beta-helper`, and
`nq-synthetic-cache-result-helper`, plus the Python conformance specimen.
Installing the package does not admit or execute any helper; watcher admission
remains a separate explicit operation.

The generated binary package has deliberately conservative maintainer-script
semantics:

- `postinst` creates the locked `nq` daemon and separate `nq-helper` helper
  accounts plus standard directories. It
  never creates or replaces `/etc/nq/nq.toml`, initializes a database, admits a
  helper, runs a migration, enables a unit, or starts the daemon.
- `prerm` stops `nqd` before a binary upgrade and leaves it stopped. After the
  package transaction, the operator must run the explicit upgrade checks and
  start the service. Removal disables and stops the unit. On a systemd host,
  either lifecycle path fails closed if the systemctl operation fails or the
  unit's resulting active state is anything other than exactly `inactive`.
- `postrm purge` retains `/etc/nq`, `/var/lib/nq`, backups, admissions, and the
  `nq` and `nq-helper` accounts. This is intentional: Debian's `purge` flag is
  not sufficient evidence that durable operational records should be
  destroyed.

There is no package-owned conffile. The sample configuration is installed only
under `/usr/share/doc/nq-ng/examples/`. The explicit, destructive local-state
purge procedure is documented in `docs/OPERATIONS.md`.

The public operator executable is `/usr/bin/nq`, which is also owned by
Debian's unrelated `nq` package. The generated package declares `Conflicts`
without `Replaces`, so `dpkg -i` refuses while the other package remains
installed instead of removing it or silently overwriting that file. Removing
the other package is a separate, visible operator decision.
