# TLS test fixtures

For `sonda upload --ca-cert`'s tests (`crates/sonda/src/upload.rs`). **Test
use only: never trust these certificates anywhere else.**

- `ca.crt`: a certificate authority whose key was discarded after signing
  `server.crt`, so nothing else can ever be signed with it.
- `server.crt`, `server.key`: a server certificate for `127.0.0.1` and
  `localhost`, signed by `ca.crt`, and its key, for the tests' TLS server.
- `other-ca.crt`: an unrelated authority, which `server.crt` doesn't chain to.

All are ECDSA P-256 and valid until 2126, generated with OpenSSL 3.6 on
2026-11-07.
