# Contributions

This is OmniTrust Security LLC's maintained downstream fork of
[Smallstep PKCS7](https://github.com/smallstep/pkcs7). General bug fixes and
features should be contributed to Smallstep under its contribution and licensing
policies. Direct external contributions to this fork are not accepted.

OmniTrust maintains its downstream changes here and synchronizes reviewed
upstream updates. Preserve upstream module paths, MIT terms, and Go BSD notices.
Original OmniTrust additions and modifications use Apache License 2.0 as
described in [LICENSE](LICENSE) and [LICENSE-APACHE](LICENSE-APACHE).

## Maintainer validation

Use the Go versions in `.github/workflows/ci.yml`. The inherited test suite
uses SHA-1-signed certificate chains and requires `GODEBUG=x509sha1=1` on Go
1.23. Go 1.24 and newer removed that setting; SHA-1 certificate-chain tests fail
on those toolchains. This does not remove SHA-1 PKCS7 message signature support.

```sh
go build ./...
go vet ./...
GODEBUG=x509sha1=1 go test -count=1 ./...
GODEBUG=x509sha1=1 go test -race ./...
```

Install `openssl` for interoperability tests. Keep upstream synchronization
changes focused and preserve regression tests for the downstream encryption
APIs. Applications and libraries using those APIs need their own pinned module
replacement, as documented in the README.

Enable private vulnerability reporting before advertising this fork's reporting
link. Security reports must remain private until a fix and disclosure are agreed.
