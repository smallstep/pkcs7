# pkcs7

[![Go Reference](https://pkg.go.dev/badge/github.com/smallstep/pkcs7.svg)](https://pkg.go.dev/github.com/smallstep/pkcs7)
[![Build Status](https://github.com/smallstep/pkcs7/workflows/CI/badge.svg?query=branch%3Amain+event%3Apush)](https://github.com/smallstep/pkcs7/actions/workflows/ci.yml?query=branch%3Amain+event%3Apush)

pkcs7 implements parsing and creating signed and enveloped messages.

This is OmniTrust Security LLC's fork of
[Smallstep PKCS7](https://github.com/smallstep/pkcs7), adding per-call content
encryption selection with `EncryptWithAlgorithm`, Triple DES CBC support, and
inspection of envelope encryption algorithms with `ContentEncryptionAlgorithmID`.
The module path remains `github.com/smallstep/pkcs7`. The badges above refer to
upstream Smallstep PKCS7.

## Installation

The fork retains upstream module paths and imports. Each consuming application
must replace upstream PKCS7 with this fork in its own `go.mod`. Replacements in
library dependencies do not propagate to consumers.

Replace `COMMIT_HASH` with a published fork commit (or use a published tag):

```sh
go mod edit -replace=github.com/smallstep/pkcs7=github.com/otpki/pkcs7@COMMIT_HASH
go mod tidy
```

Libraries using fork-specific APIs also need the replacement for their own
builds and tests, while continuing to import `github.com/smallstep/pkcs7`.
Consumers of the earlier OTPKI module-path migration must return imports to
`github.com/smallstep/pkcs7` before using this fork.

## Usage

```go
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/smallstep/pkcs7"
)

func SignAndDetach(content []byte, cert *x509.Certificate, privkey *rsa.PrivateKey) (signed []byte, err error) {
	toBeSigned, err := pkcs7.NewSignedData(content)
	if err != nil {
		return nil, fmt.Errorf("Cannot initialize signed data: %w", err)
	}
	if err = toBeSigned.AddSigner(cert, privkey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("Cannot add signer: %w", err)
	}

	// Detach signature, omit if you want an embedded signature
	toBeSigned.Detach()

	signed, err = toBeSigned.Finish()
	if err != nil {
		return nil, fmt.Errorf("Cannot finish signing data: %w", err)
	}

	// Verify the signature
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse our signed data: %w", err)
	}

	// since the signature was detached, reattach the content here
	p7.Content = content

	if bytes.Compare(content, p7.Content) != 0 {
		return nil, fmt.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
	}
	if err = p7.Verify(); err != nil {
		return nil, fmt.Errorf("Cannot verify our signed data: %w", err)
	}

	return signed, nil
}
```


## Credits

This fork is based on [smallstep/pkcs7](https://github.com/smallstep/pkcs7),
which derives from [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7)
and [fullsailor/pkcs7](https://github.com/fullsailor/pkcs7).


## Contributions and upstream synchronization

General fixes and features should be submitted to
[Smallstep PKCS7](https://github.com/smallstep/pkcs7), following upstream's
contribution and licensing policies. This fork does not accept direct external
contributions; OmniTrust maintains its downstream changes here and imports
reviewed upstream updates. See [CONTRIBUTING.md](CONTRIBUTING.md).

Report vulnerabilities affecting upstream through
[Smallstep's security policy](https://github.com/smallstep/pkcs7/security/policy).
For vulnerabilities specific to this fork, use
[private vulnerability reporting](https://github.com/otpki/pkcs7/security/advisories/new).

## License

Original PKCS7 code remains licensed under the MIT terms in [LICENSE](LICENSE).
Original additions and modifications copyright (c) 2026 OmniTrust Security LLC
are licensed under the [Apache License, Version 2.0](LICENSE-APACHE).

Existing upstream and third-party attribution and terms remain applicable,
including the Go BSD licenses in [internal/cryptobyte/LICENSE](internal/cryptobyte/LICENSE)
and [internal/legacy/x509/LICENSE](internal/legacy/x509/LICENSE), and the
[Go patent grant](internal/cryptobyte/PATENTS).
