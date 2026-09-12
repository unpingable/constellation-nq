# Constellation NQ contributor guidance

`constellation-nq` is a public developer-preview Rust workspace. Preserve the
`nq-*` crate, binary, schema, service, and filesystem identities unless a
separate compatibility decision authorizes a change.

Public changes must describe implemented behavior and stated limits precisely.
Do not claim production deployment, authority transfer from classic NQ,
complete host qualification, a general provider integration, or automatic
service activation. Package installation remains inert: it must not create
configuration, initialize state, admit helpers, or enable/start services.

Keep product fixtures distinct from qualification records. Do not add local
campaign artifacts, VM images, package outputs, credentials, account
configuration, or runtime databases to Git. Release changes require the focused
gate in `docs/PUBLIC_RELEASE.md`; only the release owner may create a new release
tag or change remote visibility. Do not move a frozen tag. Keep the four
versioned descriptors in `profiles/manifest.json` and their limits explicit.

The workspace requires Rust 1.94. Prefer focused tests for a changed component;
run the complete release gate only under the release owner's recorded resource
envelope. Do not force-push, rewrite history, or alter a frozen tag.
