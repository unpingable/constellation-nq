# Pass exact configuration bytes from a local caller

On Linux, a caller may supply `--config /proc/self/fd/N` for its explicitly
inherited descriptor (N >= 3). NQ accepts this exact canonical reference only
when it names a regular file with all four kernel seals: WRITE, GROW, SHRINK and
SEAL. It checks the inherited descriptor and opened handle identity and seals
before reading. The ordinary 1 MiB size, UTF-8, strict TOML and configuration
validation rules still apply. Unsealed files, pipes, standard streams, aliases
and malformed references refuse. Ordinary named configuration files continue
to reject final symlinks.

The caller must capture and hash the configuration it intended to enroll, seal
the bytes, and keep that descriptor inherited/open throughout the child call.
NQ reads from byte zero independently of the writer's offset. This supplies an
immutable configuration snapshot, not immutable SQLite target data, credentials,
permission to perform work, or authority to start services. NQ still performs
the selected command's existing checks. There is no fallback to another file.

The reference contains no secret value. Do not log or publish configuration
contents merely because the descriptor is sealed. Filesystem locators inside
the document must remain explicit, valid and accessible in the child environment.
This is a local Linux integration surface; no network or provider is involved.

Native qualification of this additive interface is pending. Existing source
releases without this interface correctly refuse such final-symlink references;
do not advertise them as compatible with a caller requiring sealed configuration.
