# Python conformance helper

`nq_conformance_helper.py` is a deliberately tiny, standard-library-only
implementation of `nq.helper.v1` over one-shot stdio and a supervised Unix
socket. It proves that the wire contract is JSON rather than a Rust
serialization ABI. It is not a supported Python SDK and implements only the
compiled `nq.conformance` profile version 1.

The helper reads exactly one LF-terminated request, emits exactly one
LF-terminated response, and writes no logs to stdout. The fixture scope is:

```json
{"kind":"fixture","value":{"id":"fixture-1","nonce":"nonce-123"}}
```

For the persistent carrier, set `NQ_HELPER_SOCKET` to a fresh absolute path in
a directory owned by the helper's uid and not writable by its group or other
users. The helper creates only the socket (mode `0600`), accepts exactly one
supervisor connection, and processes sequential request/response exchanges
until EOF or a termination signal. It never creates the parent directory or
replaces an existing path. The supervisor remains responsible for checking the
child's peer credentials.

Run its black-box test directly with:

```sh
python3 helpers/python-conformance/test_helper.py
```
