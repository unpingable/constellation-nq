# systemd integration

`nq-recurring-office.service` and `.timer` are optional disabled artifacts for
the finite recurring office documented in
`docs/BOUNDED_RECURRING_DIAGNOSTIC_OFFICE_V1.md`. The timer is only a wakeup;
the content-addressed deployment policy and immutable finite enrollment own
cadence and trigger authority. Package installation never creates an
enrollment, writes `/etc/nq/recurring-office.env`, or enables the timer.

`nqd.service` runs the daemon as the unprivileged `nq` account and the packaged
helpers as the separate `nq-helper` account. A configured name or numeric UID
is resolved during admission, and its exact UID/primary GID is bound into the
execution identity. Root, the daemon UID, and the daemon primary GID are
refused.

The default account is shared convenience, not a security boundary between
watchers. Every helper using `nq-helper` occupies the same Unix-identity
failure and denial-of-service domain. Deploy separate admitted helper accounts
where watchers do not share trust and availability requirements.

The closed Linode origin helper uses the separate `nq-origin-helper` account.
Its fixed signing-key path is outside `/var/lib/nq`, so the `nq` supervisor and
the ordinary `nq-helper` watcher account have no DAC read grant. The package
creates only the empty `0700` state directory; it never creates a signing key,
chooses a bootstrap coordinate, or performs a V3 acquisition. A Linode
deployment should additionally apply a service-local network policy that
allows the NQ child cgroup to reach only `169.254.169.254/32` when no admitted
watcher requires another network destination. That is deployment policy, not
metadata proof and not a reason to change the host-wide firewall.

The daemon receives only `CAP_SETUID`, `CAP_SETGID`, `CAP_CHOWN`, and
`CAP_KILL`. They are respectively needed to enter the admitted account, clear
and set the primary group, take exact-inode custody of a helper-created Unix
socket, and terminate/reap a distinct-UID process group. The isolated child
clears supplementary groups, all inheritable/permitted/effective/ambient
capabilities, and sets `no_new_privs` before helper exec. The unit grants no
device access, `CAP_DAC_OVERRIDE`, or administrative capability. A future
hardware helper still requires a separately reviewed deployment boundary;
broadening the service unit is not an admission mechanism.

Each helper is also confined to its launch process group: an inherited seccomp
filter rejects process-group and namespace escape, and NQ kills the group
before reaping its leader. Configured rlimits are per process/file or, for
NPROC, per execution UID. The unit repeats file-size/core ceilings for every
child and adds aggregate memory, CPU, and task cgroup limits plus separate
64 MiB private filesystems for `/tmp` and `/var/tmp`; none is a per-instance
cgroup quota.

Before loading configuration, the intact packaged unit changes to `/usr` and
checks every installed release byte named by
`/usr/share/nq/MANIFEST.sha256`. A changed or missing packaged profile,
contract, fixture, helper, binary, or document then prevents startup. The unit
is also listed in the manifest, so an offline manifest or package verification
detects its drift. The startup check cannot defend against replacing or
reloading the unit with one that removes the check, or against replacing both
root-owned payload bytes and the manifest. This is a local drift check over the
exact release payload, not a signature; the outer `.deb`/tarball checksum
remains the custody anchor.

Systemd creates `/run/nq` as `0751`; the API socket itself remains `0660` and
group protected. A privileged `ExecStartPre` resets `/run/nq/helpers` to
`0711` and `nq:nq`, matching tmpfiles. Random names cannot be listed, but an
isolated helper can traverse the path NQ supplies. Each persistent helper gets
a daemon-owned `0730` directory grouped to its admitted primary GID. It can
bind but not list the directory. NQ pins the helper-owned `0600` socket with
`O_PATH|O_NOFOLLOW`, takes that exact inode to `nq:nq`, rechecks it, then
connects and verifies the exact child PID, admitted UID, and primary GID with
`SO_PEERCRED`. No pathname-following mutation occurs after the socket is
pinned. Before creating a private directory, NQ pins `/run/nq/helpers` and
requires its canonical inode, exact `nq:nq` ownership, mode `0711`, no POSIX
ACL, and protected real-directory ancestors.

The service is not started by package installation. Before enabling it, an
operator must create `/etc/nq/nq.toml`, run `nq init`, admit each configured
watcher, and run `nq doctor`. Admission and doctor must use the documented
transient maintenance unit because both execute or runtime-verify under the
separate watcher UID; a plain `sudo -u nq` process lacks the four narrowly
bounded parent capabilities. See `docs/OPERATIONS.md`.

## Why there is no `nqd.socket`

The developer-preview daemon owns `/run/nq/nqd.sock`: it binds the socket,
sets mode `0660`, and removes only a pre-existing socket node. It does not yet
consume `LISTEN_FDS` or any other socket-activation interface. Shipping a
systemd socket unit now would create two owners for the same path and can
unlink systemd's listening socket while retaining an unreachable file
descriptor.

Do not add or enable an `nqd.socket` unit until `nqd` explicitly supports an
inherited descriptor and has a black-box restart test. The current socket is
still lifecycle-safe: `RuntimeDirectory=nq` creates its parent and systemd
removes the runtime directory after the service stops. Access is controlled by
the `nq` group and the socket's `0660` mode.

Configuration reload is also not implemented. Stop `nqd` before applying a
configuration change, then validate and restart it. Admission rotation,
rollback, and revocation instead use the per-instance cross-process lifecycle
lock; the daemon observes the binding event and quiesces a superseded
persistent helper.
