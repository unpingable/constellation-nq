# Runtime path POSIX ACL inspection

[NQ #3](https://github.com/unpingable/constellation-nq/issues/3), bounded product diagnosis, 2026-10-01.

NQ's path permission checks reason about owner/group/other mode bits and therefore must refuse extended POSIX access/default ACLs. The presence or enumeration of unrelated xattrs is not part of that contract.

The pinned Ubuntu 22.04 builder reproduced a name-list assumption failure on overlay `/tmp` as UID 1000: `flistxattr(fd,NULL,0)` returned 23 bytes while reading the list returned zero bytes. Exact `fgetxattr` queries for both ACL names returned ENODATA. The directory carried no POSIX ACL; refusal was caused by filesystem/UID name visibility, not a package-install error or a required ACL. A normal ext4 Jammy VM need not reproduce this particular overlay result, but list size equality is not a portable ACL property on Linux. VM installation/runtime behavior is measured separately during M2.

The product checks the two exact NUL-terminated ACL names on the already-open descriptor. Any present ACL is refused; ENODATA or unsupported attributes mean absence; every other inspection error fails closed. No pathname/symlink, ownership, mode-bit, helper account or containment check is relaxed. Ordinary tests cover absent ACL, unrelated metadata and a real extended ACL refusal.
