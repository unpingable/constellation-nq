# NQ installed operation

The prepared combined candidate targets Ubuntu 22.04 amd64. Use its source-free
[operator guide](https://github.com/unpingable/unpingable-site/blob/dev/operator-beta/constellation/combined-candidate/README.md) for download verification, exact package installation,
separate enrollment, Workbench, currentness and day-two recovery. It is a neutral
owner-review candidate; BC1 is not tagged or published. Component source alone
does not install the composed product or grant authority.

The selected collector/store/profile owner determines configuration and startup.
Use the candidate's documented enrollment; do not run two collectors against one
store. `nqd.service` is disabled until configured and explicitly enabled. The
Workbench local exercise uses its separately enrolled `nqd-ops.service` instead.

Inspect `nq --build-info`, service status and journal, then the source-defined
`nq --help` commands for diagnosis. Successful transport or a running service
does not establish current same-boot evidence. Missing/stale/refused evidence
stays visible until collection and native admission recover.

Before replacing a helper/generation, preserve state and owner-managed rollback,
stop its writer and follow the combined day-two procedure. A replaced executable
inode may invalidate admission; a package reinstall never renews effect authority.
Removal stops the packaged collector but preserves user state. Stop any separately
enrolled collector before package removal. Purge is not a state-recovery procedure.
