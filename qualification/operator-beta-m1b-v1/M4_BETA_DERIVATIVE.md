# M4 beta package derivative

This candidate changes only the existing two-VM producer's enrolled package
and owner-result pins. Relative to accepted retirement harness `7886222`, the
producer changes only NQ package/result constants. AG runtime/package and
its store-audit pointer remain exact unchanged inputs. No new runtime or
VM qualification is claimed by this note.

NQ package result owner: `491914640612960e393e8da7c1c0d1280002330c`,
`docs/M3_NATIVE_PACKAGE_RESULT.md`. Packaged runtime remains
`920dc7621f5cdf768473cef26311294fdf6cf61c`; its Debian package SHA256 is
`bb9b89fbe87d2b9b720de497c8a8f96e00aabfeadb0a7598fe0acc8c4fed76ca`.
Builder receipts and independent package inspection are not installation
acceptance. Original M2 and retirement subjects/evidence remain immutable.

The unchanged 37 producer tests pass on this derivative. The composed M4
producer/checker must pin its exact committed revision/tree, run preflight,
and receive separate independent actual VM acceptance. No VM was launched
while preparing this derivative.
