package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	fixture := UnmarshalTestFixture(SignedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}

	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}

	expected := []byte("We the People")
	if !bytes.Equal(p7.Content, expected) {
		t.Errorf("Signed content does not match.\n\tExpected:%s\n\tActual:%s", expected, p7.Content)
	}
}

func TestInvalidSigningTime(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating ECDSA key: %v", err)
	}

	// define certificate validity to a timeframe in the past, so that
	// the certificate itself is not valid at the time of signing.
	notBefore := time.Now().UTC().Round(time.Minute).Add(-2 * time.Hour)
	notAfter := time.Now().UTC().Round(time.Minute).Add(-1 * time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "TestInvalidSigningtime",
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("failed creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed parsing certificate: %v", err)
	}

	toBeSignedData, err := NewSignedData([]byte("test-invalid-signing-time"))
	if err != nil {
		t.Fatalf("failed creating signed data: %v", err)
	}

	// add the signer cert, and add attributes, including the signing
	// time attribute, containing the current time
	if err := toBeSignedData.AddSigner(cert, key, SignerInfoConfig{}); err != nil {
		t.Fatalf("failed adding signer: %v", err)
	}

	// finalizes the signed data
	signedData, err := toBeSignedData.Finish()
	if err != nil {
		t.Fatalf("failed signing data: %v", err)
	}

	p7, err := Parse(signedData)
	if err != nil {
		t.Fatalf("failed parsing signed data: %v", err)
	}

	signerCert := p7.GetOnlySigner()
	if !bytes.Equal(cert.Signature, signerCert.Signature) {
		t.Fatal("unexpected signer certificate obtained from P7 data")
	}

	// verify without a chain (self-signed cert), at time.Now()
	err = p7.VerifyWithChainAtTime(nil, time.Now())
	if err == nil {
		t.Fatal("expected verification error, but got nil")
	}

	signingTimeErr, ok := err.(*SigningTimeNotValidError)
	if !ok {
		t.Fatalf("expected *SigningTimeNotValidError, but got %T", err)
	}

	if signingTimeErr.NotBefore != notBefore {
		t.Errorf("expected notBefore to be %q, but got %q", notBefore, signingTimeErr.NotBefore)
	}

	if signingTimeErr.NotAfter != notAfter {
		t.Errorf("expected notAfter to be %q, but got %q", notAfter, signingTimeErr.NotAfter)
	}

	// verify without a chain (self-signed cert), but without specifying the time
	err = p7.VerifyWithChain(nil)
	if err == nil {
		t.Fatal("expected verification error, but got nil")
	}

	signingTimeErr, ok = err.(*SigningTimeNotValidError)
	if !ok {
		t.Fatalf("expected *SigningTimeNotValidError, but got %T", err)
	}

	if signingTimeErr.NotBefore != notBefore {
		t.Errorf("expected notBefore to be %q, but got %q", notBefore, signingTimeErr.NotBefore)
	}

	if signingTimeErr.NotAfter != notAfter {
		t.Errorf("expected notAfter to be %q, but got %q", notAfter, signingTimeErr.NotAfter)
	}
}

var SignedTestFixture = `
-----BEGIN PKCS7-----
MIIDVgYJKoZIhvcNAQcCoIIDRzCCA0MCAQExCTAHBgUrDgMCGjAcBgkqhkiG9w0B
BwGgDwQNV2UgdGhlIFBlb3BsZaCCAdkwggHVMIIBQKADAgECAgRpuDctMAsGCSqG
SIb3DQEBCzApMRAwDgYDVQQKEwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3Rh
cmswHhcNMTUwNTA2MDQyNDQ4WhcNMTYwNTA2MDQyNDQ4WjAlMRAwDgYDVQQKEwdB
Y21lIENvMREwDwYDVQQDEwhKb24gU25vdzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEAqr+tTF4mZP5rMwlXp1y+crRtFpuLXF1zvBZiYMfIvAHwo1ta8E1IcyEP
J1jIiKMcwbzeo6kAmZzIJRCTezq9jwXUsKbQTvcfOH9HmjUmXBRWFXZYoQs/OaaF
a45deHmwEeMQkuSWEtYiVKKZXtJOtflKIT3MryJEDiiItMkdybUCAwEAAaMSMBAw
DgYDVR0PAQH/BAQDAgCgMAsGCSqGSIb3DQEBCwOBgQDK1EweZWRL+f7Z+J0kVzY8
zXptcBaV4Lf5wGZJLJVUgp33bpLNpT3yadS++XQJ+cvtW3wADQzBSTMduyOF8Zf+
L7TjjrQ2+F2HbNbKUhBQKudxTfv9dJHdKbD+ngCCdQJYkIy2YexsoNG0C8nQkggy
axZd/J69xDVx6pui3Sj8sDGCATYwggEyAgEBMDEwKTEQMA4GA1UEChMHQWNtZSBD
bzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrAgRpuDctMAcGBSsOAwIaoGEwGAYJKoZI
hvcNAQkDMQsGCSqGSIb3DQEHATAgBgkqhkiG9w0BCQUxExcRMTUwNTA2MDAyNDQ4
LTA0MDAwIwYJKoZIhvcNAQkEMRYEFG9D7gcTh9zfKiYNJ1lgB0yTh4sZMAsGCSqG
SIb3DQEBAQSBgFF3sGDU9PtXty/QMtpcFa35vvIOqmWQAIZt93XAskQOnBq4OloX
iL9Ct7t1m4pzjRm0o9nDkbaSLZe7HKASHdCqijroScGlI8M+alJ8drHSFv6ZIjnM
FIwIf0B2Lko6nh9/6mUXq7tbbIHa3Gd1JUVire/QFFtmgRXMbXYk8SIS
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1TCCAUCgAwIBAgIEabg3LTALBgkqhkiG9w0BAQswKTEQMA4GA1UEChMHQWNt
ZSBDbzEVMBMGA1UEAxMMRWRkYXJkIFN0YXJrMB4XDTE1MDUwNjA0MjQ0OFoXDTE2
MDUwNjA0MjQ0OFowJTEQMA4GA1UEChMHQWNtZSBDbzERMA8GA1UEAxMISm9uIFNu
b3cwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKq/rUxeJmT+azMJV6dcvnK0
bRabi1xdc7wWYmDHyLwB8KNbWvBNSHMhDydYyIijHMG83qOpAJmcyCUQk3s6vY8F
1LCm0E73Hzh/R5o1JlwUVhV2WKELPzmmhWuOXXh5sBHjEJLklhLWIlSimV7STrX5
SiE9zK8iRA4oiLTJHcm1AgMBAAGjEjAQMA4GA1UdDwEB/wQEAwIAoDALBgkqhkiG
9w0BAQsDgYEAytRMHmVkS/n+2fidJFc2PM16bXAWleC3+cBmSSyVVIKd926SzaU9
8mnUvvl0CfnL7Vt8AA0MwUkzHbsjhfGX/i+04460Nvhdh2zWylIQUCrncU37/XSR
3Smw/p4AgnUCWJCMtmHsbKDRtAvJ0JIIMmsWXfyevcQ1ceqbot0o/LA=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICXgIBAAKBgQCqv61MXiZk/mszCVenXL5ytG0Wm4tcXXO8FmJgx8i8AfCjW1rw
TUhzIQ8nWMiIoxzBvN6jqQCZnMglEJN7Or2PBdSwptBO9x84f0eaNSZcFFYVdlih
Cz85poVrjl14ebAR4xCS5JYS1iJUople0k61+UohPcyvIkQOKIi0yR3JtQIDAQAB
AoGBAIPLCR9N+IKxodq11lNXEaUFwMHXc1zqwP8no+2hpz3+nVfplqqubEJ4/PJY
5AgbJoIfnxVhyBXJXu7E+aD/OPneKZrgp58YvHKgGvvPyJg2gpC/1Fh0vQB0HNpI
1ZzIZUl8ZTUtVgtnCBUOh5JGI4bFokAqrT//Uvcfd+idgxqBAkEA1ZbP/Kseld14
qbWmgmU5GCVxsZRxgR1j4lG3UVjH36KXMtRTm1atAam1uw3OEGa6Y3ANjpU52FaB
Hep5rkk4FQJBAMynMo1L1uiN5GP+KYLEF5kKRxK+FLjXR0ywnMh+gpGcZDcOae+J
+t1gLoWBIESH/Xt639T7smuSfrZSA9V0EyECQA8cvZiWDvLxmaEAXkipmtGPjKzQ
4PsOtkuEFqFl07aKDYKmLUg3aMROWrJidqsIabWxbvQgsNgSvs38EiH3wkUCQQCg
ndxb7piVXb9RBwm3OoU2tE1BlXMX+sVXmAkEhd2dwDsaxrI3sHf1xGXem5AimQRF
JBOFyaCnMotGNioSHY5hAkEAxyXcNixQ2RpLXJTQZtwnbk0XDcbgB+fBgXnv/4f3
BCvcu85DqJeJyQv44Oe1qsXEX9BfcQIOVaoep35RPlKi9g==
-----END PRIVATE KEY-----`

func TestVerifyWithHasher(t *testing.T) {
	fixture := UnmarshalTestFixture(HashCalcSignedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}

	const longBuffer = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam a molestie odio, id accumsan dolor. Praesent ultricies enim et pharetra molestie. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Curabitur vitae pellentesque tortor. Curabitur nulla mi, semper non lectus nec, auctor euismod tellus. Nunc vestibulum nisi quis felis efficitur, vel finibus nunc vehicula. Mauris ipsum mi, eleifend in urna non, pellentesque facilisis turpis. Ut eleifend viverra imperdiet. Vestibulum ut ligula non nunc vestibulum lobortis. Curabitur at elementum nisl. Sed facilisis ligula in pulvinar aliquet. Sed semper interdum ipsum quis hendrerit."
	p7.Content = []byte(longBuffer)
	p7.Hasher = &testHasher{}

	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

func TestVerifyWithHasherError(t *testing.T) {
	fixture := UnmarshalTestFixture(HashCalcSignedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}

	dummyError := fmt.Errorf("dummy error")
	p7.Hasher = &testHasher{retErr: dummyError}

	if err := p7.Verify(); err != dummyError {
		t.Errorf("Verify did not return expected error: %v", err)
	}
}

type testHasher struct {
	retErr error
}

func (m *testHasher) Hash(hashFunc crypto.Hash, reader io.Reader) ([]byte, error) {
	if m.retErr != nil {
		return nil, m.retErr
	}

	if !hashFunc.Available() {
		return nil, fmt.Errorf("hash function %v not available", hashFunc)
	}

	h := hashFunc.New()

	bufferSize := 128
	buffer := make([]byte, bufferSize)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			h.Write(buffer[:count])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}

var HashCalcSignedTestFixture = `
-----BEGIN PKCS7-----
MIIIjgYJKoZIhvcNAQcCoIIIfzCCCHsCAQExCTAHBgUrDgMCGjCCApAGCSqGSIb3
DQEHAaCCAoEEggJ9TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3Rl
dHVyIGFkaXBpc2NpbmcgZWxpdC4gTmFtIGEgbW9sZXN0aWUgb2RpbywgaWQgYWNj
dW1zYW4gZG9sb3IuIFByYWVzZW50IHVsdHJpY2llcyBlbmltIGV0IHBoYXJldHJh
IG1vbGVzdGllLiBMb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCwgY29uc2VjdGV0
dXIgYWRpcGlzY2luZyBlbGl0LiBDdXJhYml0dXIgdml0YWUgcGVsbGVudGVzcXVl
IHRvcnRvci4gQ3VyYWJpdHVyIG51bGxhIG1pLCBzZW1wZXIgbm9uIGxlY3R1cyBu
ZWMsIGF1Y3RvciBldWlzbW9kIHRlbGx1cy4gTnVuYyB2ZXN0aWJ1bHVtIG5pc2kg
cXVpcyBmZWxpcyBlZmZpY2l0dXIsIHZlbCBmaW5pYnVzIG51bmMgdmVoaWN1bGEu
IE1hdXJpcyBpcHN1bSBtaSwgZWxlaWZlbmQgaW4gdXJuYSBub24sIHBlbGxlbnRl
c3F1ZSBmYWNpbGlzaXMgdHVycGlzLiBVdCBlbGVpZmVuZCB2aXZlcnJhIGltcGVy
ZGlldC4gVmVzdGlidWx1bSB1dCBsaWd1bGEgbm9uIG51bmMgdmVzdGlidWx1bSBs
b2JvcnRpcy4gQ3VyYWJpdHVyIGF0IGVsZW1lbnR1bSBuaXNsLiBTZWQgZmFjaWxp
c2lzIGxpZ3VsYSBpbiBwdWx2aW5hciBhbGlxdWV0LiBTZWQgc2VtcGVyIGludGVy
ZHVtIGlwc3VtIHF1aXMgaGVuZHJlcml0LqCCBI8wggItMIIBlqADAgECAgReT4E0
MA0GCSqGSIb3DQEBBQUAMDkxEDAOBgNVBAoTB0FjbWUgQ28xJTAjBgNVBAMTHFBL
Q1M3IFRlc3QgSW50ZXJtZWRpYXRlIENlcnQwHhcNMjUwMjAyMTgxNzAzWhcNMjYw
MjAyMTgxNzA0WjAzMRAwDgYDVQQKEwdBY21lIENvMR8wHQYDVQQDExZQS0NTNyBU
ZXN0IFNpZ25lciBDZXJ0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvMS2h
EtmDRbmN83sWNs7nn4IpQlLJxS6yQoqBvRA8ZlSR57UbrOmJD/c1x+BBQUIjrkmk
xlw6TzEUTv2iVb3GoE1cd3vapUujosS2n1k4f4vIU8qDbweK9RBDC8GJSlLwi83v
gXg1/It5xVXwW9Al+Xx9v1Qr4S/YL2UvPnIEOQIDAQABo0gwRjAOBgNVHQ8BAf8E
BAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwQwHwYDVR0jBBgwFoAUJnmLplTS8997
3/Ud35byl8ofTe0wDQYJKoZIhvcNAQEFBQADgYEAUj63vKTNYJ6r9hIbnYq6AeAQ
5SHgPQ9auP/QbMm9DbEx8pJGaXgAGXxkBK8RVEFms8OCJIK+9JdGceN+aVl3FL/n
V5inmA43yuFAamD/gvhbqdxvf86/d7YgZn3ecKYaoZKaRJxGs/qbTl3XY8jDOhMz
J9m0sEPi9mUuQUst6NUwggJaMIIBw6ADAgECAgUAtGVULDANBgkqhkiG9w0BAQUF
ADAvMRAwDgYDVQQKEwdBY21lIENvMRswGQYDVQQDExJQS0NTNyBUZXN0IFJvb3Qg
Q0EwHhcNMjUwMjAyMTgxNzAzWhcNMjYwMjAyMTgxNzA0WjA5MRAwDgYDVQQKEwdB
Y21lIENvMSUwIwYDVQQDExxQS0NTNyBUZXN0IEludGVybWVkaWF0ZSBDZXJ0MIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvMS2hEtmDRbmN83sWNs7nn4IpQlLJ
xS6yQoqBvRA8ZlSR57UbrOmJD/c1x+BBQUIjrkmkxlw6TzEUTv2iVb3GoE1cd3va
pUujosS2n1k4f4vIU8qDbweK9RBDC8GJSlLwi83vgXg1/It5xVXwW9Al+Xx9v1Qr
4S/YL2UvPnIEOQIDAQABo3gwdjAOBgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYI
KwYBBQUHAwQwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJnmLplTS89973/Ud
35byl8ofTe0wHwYDVR0jBBgwFoAUJnmLplTS89973/Ud35byl8ofTe0wDQYJKoZI
hvcNAQEFBQADgYEAZ3EEdFK3otrKGlGvGJJrdzdBYzxnq/J7+VlhWBNNapBaMiBc
hoTQDOrGHkzST6NezqzwTzLEEl+RRecpGJFDlj3+P5BFIeRGpUyf55nZjRJEmYer
j4iLuLyoMTeU1grLAFy0zp78x4AjDT/6GiqKlXZX/YbZaODQyUjjhuISJ4cxggFC
MIIBPgIBATBBMDkxEDAOBgNVBAoTB0FjbWUgQ28xJTAjBgNVBAMTHFBLQ1M3IFRl
c3QgSW50ZXJtZWRpYXRlIENlcnQCBF5PgTQwBwYFKw4DAhqgXTAYBgkqhkiG9w0B
CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNTAyMDIxODE3MDRaMCMG
CSqGSIb3DQEJBDEWBBQuICjf8Q5uyWggGVKRZeomIoxeQjALBgkqhkiG9w0BAQUE
gYCV3EPgmvq5IgP9yGrKfyrT2v5+Caw3aUkAC8rdi+NQME0FR0Ov0DCHfrgr8CR9
+d16d5vQZFrSKKocQmT/Jm30ggrrS6yVDIODt1c3qdkItnp9W67l7pEly87Wpwi/
0X418iR3Q/g0kDj0Vw52dS2dJsFuebD1ZU/JPveXvywGcw==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIICLTCCAZagAwIBAgIEXk+BNDANBgkqhkiG9w0BAQUFADA5MRAwDgYDVQQKEwdB
Y21lIENvMSUwIwYDVQQDExxQS0NTNyBUZXN0IEludGVybWVkaWF0ZSBDZXJ0MB4X
DTI1MDIwMjE4MTcwM1oXDTI2MDIwMjE4MTcwNFowMzEQMA4GA1UEChMHQWNtZSBD
bzEfMB0GA1UEAxMWUEtDUzcgVGVzdCBTaWduZXIgQ2VydDCBnzANBgkqhkiG9w0B
AQEFAAOBjQAwgYkCgYEArzEtoRLZg0W5jfN7FjbO55+CKUJSycUuskKKgb0QPGZU
kee1G6zpiQ/3NcfgQUFCI65JpMZcOk8xFE79olW9xqBNXHd72qVLo6LEtp9ZOH+L
yFPKg28HivUQQwvBiUpS8IvN74F4NfyLecVV8FvQJfl8fb9UK+Ev2C9lLz5yBDkC
AwEAAaNIMEYwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMEMB8G
A1UdIwQYMBaAFCZ5i6ZU0vPfe9/1Hd+W8pfKH03tMA0GCSqGSIb3DQEBBQUAA4GB
AFI+t7ykzWCeq/YSG52KugHgEOUh4D0PWrj/0GzJvQ2xMfKSRml4ABl8ZASvEVRB
ZrPDgiSCvvSXRnHjfmlZdxS/51eYp5gON8rhQGpg/4L4W6ncb3/Ov3e2IGZ93nCm
GqGSmkScRrP6m05d12PIwzoTMyfZtLBD4vZlLkFLLejV
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICWjCCAcOgAwIBAgIFALRlVCwwDQYJKoZIhvcNAQEFBQAwLzEQMA4GA1UEChMH
QWNtZSBDbzEbMBkGA1UEAxMSUEtDUzcgVGVzdCBSb290IENBMB4XDTI1MDIwMjE4
MTcwM1oXDTI2MDIwMjE4MTcwNFowOTEQMA4GA1UEChMHQWNtZSBDbzElMCMGA1UE
AxMcUEtDUzcgVGVzdCBJbnRlcm1lZGlhdGUgQ2VydDCBnzANBgkqhkiG9w0BAQEF
AAOBjQAwgYkCgYEArzEtoRLZg0W5jfN7FjbO55+CKUJSycUuskKKgb0QPGZUkee1
G6zpiQ/3NcfgQUFCI65JpMZcOk8xFE79olW9xqBNXHd72qVLo6LEtp9ZOH+LyFPK
g28HivUQQwvBiUpS8IvN74F4NfyLecVV8FvQJfl8fb9UK+Ev2C9lLz5yBDkCAwEA
AaN4MHYwDgYDVR0PAQH/BAQDAgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMEMA8GA1Ud
EwEB/wQFMAMBAf8wHQYDVR0OBBYEFCZ5i6ZU0vPfe9/1Hd+W8pfKH03tMB8GA1Ud
IwQYMBaAFCZ5i6ZU0vPfe9/1Hd+W8pfKH03tMA0GCSqGSIb3DQEBBQUAA4GBAGdx
BHRSt6LayhpRrxiSa3c3QWM8Z6vye/lZYVgTTWqQWjIgXIaE0Azqxh5M0k+jXs6s
8E8yxBJfkUXnKRiRQ5Y9/j+QRSHkRqVMn+eZ2Y0SRJmHq4+Ii7i8qDE3lNYKywBc
tM6e/MeAIw0/+hoqipV2V/2G2Wjg0MlI44biEieH
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICLjCCAZegAwIBAgIEDhD97zANBgkqhkiG9w0BAQsFADAvMRAwDgYDVQQKEwdB
Y21lIENvMRswGQYDVQQDExJQS0NTNyBUZXN0IFJvb3QgQ0EwHhcNMjUwMjAyMTgx
NzAzWhcNMjYwMjAyMTgxNzA0WjAvMRAwDgYDVQQKEwdBY21lIENvMRswGQYDVQQD
ExJQS0NTNyBUZXN0IFJvb3QgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB
AK8xLaES2YNFuY3zexY2zuefgilCUsnFLrJCioG9EDxmVJHntRus6YkP9zXH4EFB
QiOuSaTGXDpPMRRO/aJVvcagTVx3e9qlS6OixLafWTh/i8hTyoNvB4r1EEMLwYlK
UvCLze+BeDX8i3nFVfBb0CX5fH2/VCvhL9gvZS8+cgQ5AgMBAAGjVzBVMA4GA1Ud
DwEB/wQEAwICpDATBgNVHSUEDDAKBggrBgEFBQcDBDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBQmeYumVNLz33vf9R3flvKXyh9N7TANBgkqhkiG9w0BAQsFAAOB
gQCpWSM5epx+nsZRdH6QGLR9q1JxSZ6+IeWgccu2WLE8k3usyItTCfkVMncPqzr3
og/vYQFEMvfEyFCJy9CBpLXTjkOOuOD5M9mNaGnUMjPIpBkxtBLIaFz3qeuqDj04
5i35yuWnAykAR+6kxEbNpkMD5uHznshVU8Mum990qP9Fqg==
-----END CERTIFICATE-----`

func TestVerifyAppStore(t *testing.T) {
	fixture := UnmarshalTestFixture(AppStoreReceiptFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

var AppStoreReceiptFixture = `
-----BEGIN PKCS7-----
MIITtgYJKoZIhvcNAQcCoIITpzCCE6MCAQExCzAJBgUrDgMCGgUAMIIDVwYJKoZI
hvcNAQcBoIIDSASCA0QxggNAMAoCAQgCAQEEAhYAMAoCARQCAQEEAgwAMAsCAQEC
AQEEAwIBADALAgEDAgEBBAMMATEwCwIBCwIBAQQDAgEAMAsCAQ8CAQEEAwIBADAL
AgEQAgEBBAMCAQAwCwIBGQIBAQQDAgEDMAwCAQoCAQEEBBYCNCswDAIBDgIBAQQE
AgIAjTANAgENAgEBBAUCAwFgvTANAgETAgEBBAUMAzEuMDAOAgEJAgEBBAYCBFAy
NDcwGAIBAgIBAQQQDA5jb20uemhpaHUudGVzdDAYAgEEAgECBBCS+ZODNMHwT1Nz
gWYDXyWZMBsCAQACAQEEEwwRUHJvZHVjdGlvblNhbmRib3gwHAIBBQIBAQQU4nRh
YCEZx70Flzv7hvJRjJZckYIwHgIBDAIBAQQWFhQyMDE2LTA3LTIzVDA2OjIxOjEx
WjAeAgESAgEBBBYWFDIwMTMtMDgtMDFUMDc6MDA6MDBaMD0CAQYCAQEENbR21I+a
8+byMXo3NPRoDWQmSXQF2EcCeBoD4GaL//ZCRETp9rGFPSg1KekCP7Kr9HAqw09m
MEICAQcCAQEEOlVJozYYBdugybShbiiMsejDMNeCbZq6CrzGBwW6GBy+DGWxJI91
Y3ouXN4TZUhuVvLvN1b0m5T3ggQwggFaAgERAgEBBIIBUDGCAUwwCwICBqwCAQEE
AhYAMAsCAgatAgEBBAIMADALAgIGsAIBAQQCFgAwCwICBrICAQEEAgwAMAsCAgaz
AgEBBAIMADALAgIGtAIBAQQCDAAwCwICBrUCAQEEAgwAMAsCAga2AgEBBAIMADAM
AgIGpQIBAQQDAgEBMAwCAgarAgEBBAMCAQEwDAICBq4CAQEEAwIBADAMAgIGrwIB
AQQDAgEAMAwCAgaxAgEBBAMCAQAwGwICBqcCAQEEEgwQMTAwMDAwMDIyNTMyNTkw
MTAbAgIGqQIBAQQSDBAxMDAwMDAwMjI1MzI1OTAxMB8CAgaoAgEBBBYWFDIwMTYt
MDctMjNUMDY6MjE6MTFaMB8CAgaqAgEBBBYWFDIwMTYtMDctMjNUMDY6MjE6MTFa
MCACAgamAgEBBBcMFWNvbS56aGlodS50ZXN0LnRlc3RfMaCCDmUwggV8MIIEZKAD
AgECAggO61eH554JjTANBgkqhkiG9w0BAQUFADCBljELMAkGA1UEBhMCVVMxEzAR
BgNVBAoMCkFwcGxlIEluYy4xLDAqBgNVBAsMI0FwcGxlIFdvcmxkd2lkZSBEZXZl
bG9wZXIgUmVsYXRpb25zMUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv
cGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNTExMTMw
MjE1MDlaFw0yMzAyMDcyMTQ4NDdaMIGJMTcwNQYDVQQDDC5NYWMgQXBwIFN0b3Jl
IGFuZCBpVHVuZXMgU3RvcmUgUmVjZWlwdCBTaWduaW5nMSwwKgYDVQQLDCNBcHBs
ZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczETMBEGA1UECgwKQXBwbGUg
SW5jLjELMAkGA1UEBhMCVVMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQClz4H9JaKBW9aH7SPaMxyO4iPApcQmyz3Gn+xKDVWG/6QC15fKOVRtfX+yVBid
xCxScY5ke4LOibpJ1gjltIhxzz9bRi7GxB24A6lYogQ+IXjV27fQjhKNg0xbKmg3
k8LyvR7E0qEMSlhSqxLj7d0fmBWQNS3CzBLKjUiB91h4VGvojDE2H0oGDEdU8zeQ
uLKSiX1fpIVK4cCc4Lqku4KXY/Qrk8H9Pm/KwfU8qY9SGsAlCnYO3v6Z/v/Ca/Vb
XqxzUUkIVonMQ5DMjoEC0KCXtlyxoWlph5AQaCYmObgdEHOwCl3Fc9DfdjvYLdmI
HuPsB8/ijtDT+iZVge/iA0kjAgMBAAGjggHXMIIB0zA/BggrBgEFBQcBAQQzMDEw
LwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtd3dkcjA0
MB0GA1UdDgQWBBSRpJz8xHa3n6CK9E31jzZd7SsEhTAMBgNVHRMBAf8EAjAAMB8G
A1UdIwQYMBaAFIgnFwmpthhgi+zruvZHWcVSVKO3MIIBHgYDVR0gBIIBFTCCAREw
ggENBgoqhkiG92NkBQYBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9u
IHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5j
ZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25k
aXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0
aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRwOi8vd3d3
LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wDgYDVR0PAQH/BAQDAgeA
MBAGCiqGSIb3Y2QGCwEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQANphvTLj3jWysH
bkKWbNPojEMwgl/gXNGNvr0PvRr8JZLbjIXDgFnf4+LXLgUUrA3btrj+/DUufMut
F2uOfx/kd7mxZ5W0E16mGYZ2+FogledjjA9z/Ojtxh+umfhlSFyg4Cg6wBA3Lbmg
BDkfc7nIBf3y3n8aKipuKwH8oCBc2et9J6Yz+PWY4L5E27FMZ/xuCk/J4gao0pfz
p45rUaJahHVl0RYEYuPBX/UIqc9o2ZIAycGMs/iNAGS6WGDAfK+PdcppuVsq1h1o
bphC9UynNxmbzDscehlD86Ntv0hgBgw2kivs3hi1EdotI9CO/KBpnBcbnoB7OUdF
MGEvxxOoMIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjEL
MAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxl
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENB
MB4XDTEzMDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVT
MRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUg
RGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERl
dmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0
U3rOfGOAYXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkV
CBmsqtsqMu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8
V25nNYB2NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHl
d0WNUEi6Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1q
arunFjVg0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGj
gaYwgaMwHQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQF
MAMBAf8wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcw
JTAjoCGgH4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/
BAQDAgGGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Z
viz1smwvj+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/N
w0Uwj6ODDc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJ
TleMa1s8Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1V
AKmuu0swruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur
+cmV6U/kTecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxR
pVzscYqCtGwPDBUfMIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQsw
CQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUg
Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0Ew
HhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne
+Uts9QerIjAC6Bg++FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjcz
y8QPTc4UadHJGXL1XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQ
Z48ItCD3y6wsIG9wtj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCS
C7EhFi501TwN22IWq6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINB
hzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIB
djAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9Bp
R5R2Cf70a40uQKb3R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/
CF4wggERBgNVHSAEggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcC
ARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCB
thqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFz
c3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJk
IHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5
IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3
DQEBBQUAA4IBAQBcNplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizU
sZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJ
fBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr
1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltk
wGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIq
xw8dtk2cXmPIS4AXUKqK1drk/NAJBzewdXUhMYIByzCCAccCAQEwgaMwgZYxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBX
b3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29y
bGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
dHkCCA7rV4fnngmNMAkGBSsOAwIaBQAwDQYJKoZIhvcNAQEBBQAEggEAasPtnide
NWyfUtewW9OSgcQA8pW+5tWMR0469cBPZR84uJa0gyfmPspySvbNOAwnrwzZHYLa
ujOxZLip4DUw4F5s3QwUa3y4BXpF4J+NSn9XNvxNtnT/GcEQtCuFwgJ0o3F0ilhv
MTHrwiwyx/vr+uNDqlORK8lfK+1qNp+A/kzh8eszMrn4JSeTh9ZYxLHE56WkTQGD
VZXl0gKgxSOmDrcp1eQxdlymzrPv9U60wUJ0bkPfrU9qZj3mJrmrkQk61JTe3j6/
QfjfFBG9JG2mUmYQP1KQ3SypGHzDW8vngvsGu//tNU0NFfOqQu4bYU4VpQl0nPtD
4B85NkrgvQsWAQ==
-----END PKCS7-----`

func TestVerifyApkEcdsa(t *testing.T) {
	fixture := UnmarshalTestFixture(ApkEcdsaFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	p7.Content, err = base64.StdEncoding.DecodeString(ApkEcdsaContent)
	if err != nil {
		t.Errorf("Failed to decode base64 signature file: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

var ApkEcdsaFixture = `-----BEGIN PKCS7-----
MIIDAgYJKoZIhvcNAQcCoIIC8zCCAu8CAQExDzANBglghkgBZQMEAgMFADALBgkq
hkiG9w0BBwGgggH3MIIB8zCCAVSgAwIBAgIJAOxXdFsvm3YiMAoGCCqGSM49BAME
MBIxEDAOBgNVBAMMB2VjLXA1MjEwHhcNMTYwMzMxMTUzMTIyWhcNNDMwODE3MTUz
MTIyWjASMRAwDgYDVQQDDAdlYy1wNTIxMIGbMBAGByqGSM49AgEGBSuBBAAjA4GG
AAQAYX95sSjPEQqgyLD04tNUyq9y/w8seblOpfqa/Amx6H4GFdrjGXX0YTfXKr9G
hAyIyQSnNrIg0zDlWQUbBPRW4CYBLFOg1pUn1NBhKFD4NtO1KWvYtNOYDegFjRCP
B0p+fEXDbq8QFDYvlh+NZUJ16+ih8XNIf1C29xuLEqN6oKOnAvajUDBOMB0GA1Ud
DgQWBBT/Ra3kz60gQ7tYk3byZckcLabt8TAfBgNVHSMEGDAWgBT/Ra3kz60gQ7tY
k3byZckcLabt8TAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMEA4GMADCBiAJCAP39
hYLsWk2H84oEw+HJqGGjexhqeD3vSO1mWhopripE/81oy3yV10puYoJe11xDSfcD
j2VfNCHazuXO3kSxGA/1AkIBLUJxp/WYbYzhBGKr6lcxczKI/wuMfkZ6vL+0EMJV
A/2uEoeqvnl7BsdkicyaOBNEADijuVdaPPIWzKClt9OaVxExgdAwgc0CAQEwHzAS
MRAwDgYDVQQDDAdlYy1wNTIxAgkA7Fd0Wy+bdiIwDQYJYIZIAWUDBAIDBQAwCgYI
KoZIzj0EAwQEgYswgYgCQgD1pVSNo7qTm9A6tpt3SU2yRa+xpJAnUbpZ+Gu36B71
JnQBUzRgTGevniqHpyagi7b2zjWh1uvfz9FfrITUwGMddgJCAPjiBRcl7rKpxmZn
V1MvcJOX41xRSJu1wmBiYXqaJarL+gQ/Wl7RYsMtqLjmNColvLaHNxCaWOO/8nAE
Hg0OMA60
-----END PKCS7-----`

var ApkEcdsaContent = `U2lnbmF0dXJlLVZlcnNpb246IDEuMA0KU0hBLTUxMi1EaWdlc3QtTWFuaWZlc3Q6IFAvVDRqSWtTMjQvNzFxeFE2WW1MeEtNdkRPUUF0WjUxR090dFRzUU9yemhHRQ0KIEpaUGVpWUtyUzZYY090bStYaWlFVC9uS2tYdWVtUVBwZ2RBRzFKUzFnPT0NCkNyZWF0ZWQtQnk6IDEuMCAoQW5kcm9pZCBTaWduQXBrKQ0KDQpOYW1lOiBBbmRyb2lkTWFuaWZlc3QueG1sDQpTSEEtNTEyLURpZ2VzdDogcm9NbWVQZmllYUNQSjFJK2VzMVpsYis0anB2UXowNHZqRWVpL2U0dkN1ald0VVVWSHEzMkNXDQogMUxsOHZiZGMzMCtRc1FlN29ibld4dmhLdXN2K3c1a2c9PQ0KDQpOYW1lOiByZXNvdXJjZXMuYXJzYw0KU0hBLTUxMi1EaWdlc3Q6IG5aYW1aUzlPZTRBRW41cEZaaCtoQ1JFT3krb1N6a3hHdU5YZU0wUFF6WGVBVlVQV3hSVzFPYQ0KIGVLbThRbXdmTmhhaS9HOEcwRUhIbHZEQWdlcy9HUGtBPT0NCg0KTmFtZTogY2xhc3Nlcy5kZXgNClNIQS01MTItRGlnZXN0OiBlbWlDQld2bkVSb0g2N2lCa3EwcUgrdm5tMkpaZDlMWUNEV051N3RNYzJ3bTRtV0dYSUVpWmcNCiBWZkVPV083MFRlZnFjUVhldkNtN2hQMnRpT0U3Y0w5UT09DQoNCg==`

func TestVerifyFirefoxAddon(t *testing.T) {
	fixture := UnmarshalTestFixture(FirefoxAddonFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	p7.Content = FirefoxAddonContent
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(FirefoxAddonRootCert)
	// verifies at the signingTime authenticated attr
	if err := p7.VerifyWithChain(certPool); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}

	// The chain has validity:
	//
	// EE:           2016-08-17 20:04:58 +0000 UTC 2021-08-16 20:04:58 +0000 UTC
	// Intermediate: 2015-03-17 23:52:42 +0000 UTC 2025-03-14 23:52:42 +0000 UTC
	// Root:         2015-03-17 22:53:57 +0000 UTC 2025-03-14 22:53:57 +0000 UTC
	validTime := time.Date(2021, 8, 16, 20, 0, 0, 0, time.UTC)
	if err = p7.VerifyWithChainAtTime(certPool, validTime); err != nil {
		t.Errorf("Verify at UTC now failed with error: %v", err)
	}

	expiredTime := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	if err = p7.VerifyWithChainAtTime(certPool, expiredTime); err == nil {
		t.Errorf("Verify at expired time %s did not error", expiredTime)
	}
	notYetValidTime := time.Date(1999, time.July, 5, 0, 13, 0, 0, time.UTC)
	if err = p7.VerifyWithChainAtTime(certPool, notYetValidTime); err == nil {
		t.Errorf("Verify at not yet valid time %s did not error", notYetValidTime)
	}

	// Verify the certificate chain to make sure the identified root
	// is the one we expect
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, p7.Signers[0].IssuerAndSerialNumber)
	if ee == nil {
		t.Errorf("No end-entity certificate found for signer")
	}
	signingTime := mustParseTime("2017-02-23T09:06:16-05:00")
	chains, err := verifyCertChain(ee, p7.Certificates, certPool, signingTime)
	if err != nil {
		t.Error(err)
	}
	if len(chains) != 1 {
		t.Errorf("Expected to find one chain, but found %d", len(chains))
	}
	if len(chains[0]) != 3 {
		t.Errorf("Expected to find three certificates in chain, but found %d", len(chains[0]))
	}
	if chains[0][0].Subject.CommonName != "tabscope@xuldev.org" {
		t.Errorf("Expected to find EE certificate with subject 'tabscope@xuldev.org', but found '%s'", chains[0][0].Subject.CommonName)
	}
	if chains[0][1].Subject.CommonName != "production-signing-ca.addons.mozilla.org" {
		t.Errorf("Expected to find intermediate certificate with subject 'production-signing-ca.addons.mozilla.org', but found '%s'", chains[0][1].Subject.CommonName)
	}
	if chains[0][2].Subject.CommonName != "root-ca-production-amo" {
		t.Errorf("Expected to find root certificate with subject 'root-ca-production-amo', but found '%s'", chains[0][2].Subject.CommonName)
	}
}

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

var FirefoxAddonContent = []byte(`Signature-Version: 1.0
MD5-Digest-Manifest: KjRavc6/KNpuT1QLcB/Gsg==
SHA1-Digest-Manifest: 5Md5nUg+U7hQ/UfzV+xGKWOruVI=

`)

var FirefoxAddonFixture = `
-----BEGIN PKCS7-----
MIIQTAYJKoZIhvcNAQcCoIIQPTCCEDkCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3
DQEHAaCCDL0wggW6MIIDoqADAgECAgYBVpobWVwwDQYJKoZIhvcNAQELBQAwgcUx
CzAJBgNVBAYTAlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYD
VQQLEyZNb3ppbGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTExMC8G
A1UEAxMocHJvZHVjdGlvbi1zaWduaW5nLWNhLmFkZG9ucy5tb3ppbGxhLm9yZzE0
MDIGCSqGSIb3DQEJARYlc2VydmljZXMtb3BzK2FkZG9uc2lnbmluZ0Btb3ppbGxh
LmNvbTAeFw0xNjA4MTcyMDA0NThaFw0yMTA4MTYyMDA0NThaMHYxEzARBgNVBAsT
ClByb2R1Y3Rpb24xCzAJBgNVBAYTAlVTMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3
MQ8wDQYDVQQKEwZBZGRvbnMxCzAJBgNVBAgTAkNBMRwwGgYDVQQDFBN0YWJzY29w
ZUB4dWxkZXYub3JnMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv6e0
mPD8dt4J8HTNNq4ODns2DV6Weh1hllCIFvOeu1u3UrR03st0BMY8OXYwr/NvRVjg
bA8gRySWAL+XqLzbhtXNeNegAoxrF+3mYY5rJjsLj/FGI6P6OXjngqwgm9VTBl7m
jh/KXBSwYoUcavJo6cmk8sCFwoblyQiv+tsWaUCOI6zMzubNtIS+GFvET9y/VZMP
j6mk8O10wBgJF5MMtA19va3qXy7aCZ7DnZp1l3equd/L6t324TtXoqx6xWQKo6TM
I0mcTlKvm6TKegTGBCyGn3JRARoIJv4AW1qqgyaHXf9EoY2pKT8Avkri5++NuSJ6
jtO4k/diBA2MZU20U0KGffYZNTxKDqd6XtI6y1tJPd/OWRFyU+mHntkcm9sar7L3
nPKujHRox2re10ec1WBnJE3PjlAoesNjxzp+xs2mGGc8DX9NuWn+1uK9xmgGIIMl
OFfyQ4s0G6hKp5goFcrFZxmexu0ZahOs8vZf8xDBW7yR1zToQElOXHvrscM386os
kOF9IxQZfcCoPuNQVg1haCONNkx0oau3RQQlOSAZtC79b+rBjQ5JYfjRLYAworf2
xQaprCh33TD1dTBrvzEbCGszgkN53Vqh5TFBjbU/NyldOkGvK8Xf6WhT5u+aftnV
lbuE2McAg6x1AlloUZq6PNTBpz7zypcIISnQ+y8CAwEAATANBgkqhkiG9w0BAQsF
AAOCAgEAIBoo2+OEYNCgP/IbUj9azaf/lde1q4AK/uTMoUeS5WcrXd8aqA0Y1qV7
xUALgDQAExXgqcOMGu4mPMaoZDgwGI4Tj7XPJQq5Z5zYxpRf/Wtzae33T9BF6QPW
v5xiRYuol+FbEtqRHZqxDWtIrd1MWBy3wjO3pLPdzDM9jWh+HLxdGWThJszaZp3T
CqsOx+l9W0Q7qM5ioZpHStgXDfhw38Lg++kLnzcX9MqsjYyezdwE4krqW6hK3+4S
0LZE4dTgsy8JULkyAF3HrPWEXESnD7c4mx6owZe+BNDK5hsVM/obAqH7sJq/igbM
5N1l832p/ws8l5xKOr3qBWSzWn6u7ExvqG6Ckh0foJOVXvzGqvrXcoiBGV8S9Z7c
DghUvMt6b0pZ0ildRCHfTUz7eG3g4MhfbjupR7b+L9FWEJhcd/H0dxpw7SKYha/n
ePuRL7MXmbW8WLMqO/ImxzL8TPOB3pUg3nITfubV6gpPBmn+0nwbqYUmggJuwgvK
I2GpN2Ny6EErZy17EEgyhJygJZMj+UzQjC781xxsl3ljpYEqqwgRLIZBSBUD5dXj
XBuU24w162SeSyHZzkBbuv6lr52pqoZyFrG29DCHECgO9ZmNWgSpiWSkh+vExAG7
wNs0y61t2HUG+BCMGPQ9sOzouyTfrnLVAWwzswGftFYQfoIBeJIwggb7MIIE46AD
AgECAgMQAAIwDQYJKoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCVVMxHDAaBgNVBAoT
E01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEgQU1PIFByb2R1
Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290LWNhLXByb2R1Y3Rp
b24tYW1vMB4XDTE1MDMxNzIzNTI0MloXDTI1MDMxNDIzNTI0MlowgcUxCzAJBgNV
BAYTAlVTMRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMS8wLQYDVQQLEyZN
b3ppbGxhIEFNTyBQcm9kdWN0aW9uIFNpZ25pbmcgU2VydmljZTExMC8GA1UEAxMo
cHJvZHVjdGlvbi1zaWduaW5nLWNhLmFkZG9ucy5tb3ppbGxhLm9yZzE0MDIGCSqG
SIb3DQEJARYlc2VydmljZXMtb3BzK2FkZG9uc2lnbmluZ0Btb3ppbGxhLmNvbTCC
AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMLMM9m2HBLhCiO9mhljpehT
hxpzlCnxluzDZ51I/H7MvBbIvZBm9zSpHdffubSsak2qYE69d+ebTa/CK83WIosM
24/2Qp7n/GGaPJcCC4Y3JkrCsgA8+wV2MbFlKSv+qMdvI/sE3BPYDMCjVPMhHmIP
XaPWd42OoHpI8R3GGUtVnR3Hm76pa2+v6TwgeMiO8om+ogGufiyv6FNMZ5NuY1Z9
aLNEvehnAzSfddQyki+6FJd7XkgZbP7pb1Kl8yYgiy4piBerJ9H09uPehffE3Ell
3cApQL3+0kjaUX4scMjuNQDMKziRZkYgJAM+qA9WA5Jn77AjerQBWQeEev1PWHYh
0IDlgS/a0bjKmVjNZYG6adrY/R5/whzWGFCIE1UfhPm6PdN0557qvF838C2RFHsI
KzV6KQf0chMjpa02tPaIctjVhnDQZZNKm2ZfLOt9kQ57Is/e6KxH7pYMit46+s99
lYM7ZquvWbK19b1Ili/6S1BxSzd3wztgfN5jGsc+jCCYLm+AcVtfNKc8cFZHXKrB
CwhGmdbWDSBCicZNA7FKJpO3oIx26VPF2XUldA/T5Mh/POGLilK3t9m9qbjEyDp1
EwoBToOR/aMrdnNYvSWp0g/GHMzSfJjjXyAqrZY2itam/IJd8r9FoRAzevPt/zTX
BET3INoiCDGRH0XrxUYtAgMGVTejggE5MIIBNTAMBgNVHRMEBTADAQH/MA4GA1Ud
DwEB/wQEAwIBBjAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUdHxf
FKXipZLjs20GqIUdNkQXH4gwgagGA1UdIwSBoDCBnYAUs7zqWHSr4W54KrKrnCMe
qGMsl7ehgYGkfzB9MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jw
b3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5n
IFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1hbW+CAQEwMwYJ
YIZIAYb4QgEEBCYWJGh0dHA6Ly9hZGRvbnMubW96aWxsYS5vcmcvY2EvY3JsLnBl
bTANBgkqhkiG9w0BAQwFAAOCAgEArde/fdjb7TE0eH7Ij7xU4JbcSyhY3cQhVYCw
Fg+Q/2pj+NAfazcjUuLWA0Y/YZs9HOx6j+ZAqO4C/xfMP4RDs9IypxvzHDU6SXgD
RK6uOKtS07HXLcXgFUBvJEQhbT/h5+IQOA4/GcpCshfD6iyiBBi+IocR+tnKPCuZ
T3m1t60Eja/MkPKG/Gx8vSodHvlTTsJ2GzjUEANveCZOnlAdp9fjTvFZny9qqnbg
sfVbuTqKndbCFW5QLXfkna6jBqMrY0+CpMYY2oJ5gwpHbE/7hhukjxGCTcpv7r/O
M53bb/DZnybDlLLepacljvz7DBA1O1FFtEhf9MR+vyvmBpniAyKQhqG2hsVGurE1
nBcE+oteZWar2lMp6+etDAb9DRC+jZv0aEQs2o/qQwyD8AGquLgBsJq5Jz3gGxzn
4r3vGu2lV8VdzIm0C8sOFSWTmTZxQmJbF8xSsQBojnsvEah4DPER+eAt6qKolaWe
s4drJQjzFyC7HJn2VqalpCwbe9CdMB7eRqzeP6GujJBi80/gx0pAysUtuKKpH5IJ
WbXAOszfrjb3CaHafYZDnwPoOfj74ogFzjt2f54jwnU+ET/byfjZ7J8SLH316C1V
HrvFXcTzyMV4aRluVPjPg9x1G58hMIbeuT4GpwQUNdJ9uL8t65v0XwG2t6Y7jpRO
sFVxBtgxggNXMIIDUwIBATCB0DCBxTELMAkGA1UEBhMCVVMxHDAaBgNVBAoTE01v
emlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEgQU1PIFByb2R1Y3Rp
b24gU2lnbmluZyBTZXJ2aWNlMTEwLwYDVQQDEyhwcm9kdWN0aW9uLXNpZ25pbmct
Y2EuYWRkb25zLm1vemlsbGEub3JnMTQwMgYJKoZIhvcNAQkBFiVzZXJ2aWNlcy1v
cHMrYWRkb25zaWduaW5nQG1vemlsbGEuY29tAgYBVpobWVwwCQYFKw4DAhoFAKBd
MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MDgx
NzIwMDQ1OFowIwYJKoZIhvcNAQkEMRYEFAxlGvNFSx+Jqj70haE8b7UZk+2GMA0G
CSqGSIb3DQEBAQUABIICADsDlrucYRgwq9o2QSsO6X6cRa5Zu6w+1n07PTIyc1zn
Pi1cgkkWZ0kZBHDrJ5CY33yRQPl6I1tHXaq7SkOSdOppKhpUmBiKZxQRAZR21QHk
R3v1XS+st/o0N+0btv3YoplUifLIwtH89oolxqlStChELu7FuOBretdhx/z12ytA
EhIIS53o/XjDL7XKJbQA02vzOtOC/Eq6p8BI7F3y6pvtmJIRkeGv+u6ssJa6g5q8
74w8hHXaH94Z9+hDPqjNWlsXJHgPdAKiEjzDz9oLkvDyX4Pd8JMK5ILskirpG+hj
Q8jkTc5oYwyuSlBAUTGxW6ZbuOrtfVZvOVtRL/ixuiFiVlJ+JOQOxrtK19ukamsI
iacFlbLgiA7w0HCtm2DsT9aL67/1e4rJ0lv0MjnQYUMmKQy7g0Gd3+nQPU9pn+Lf
Z/UmSNWiJ8Csc/seDMyzT6jrzcGPfoSVaUowH0wGrI9If1snwcr+mMg7dWRGf1fm
y/dcVSzed0ax4LqDmike1EshU+51cKWWlnhyNHK4KH+0fNsBQ0c6clrFpGx9MPmV
YXie6C+LWkh5x12RU0sJt/SmSZV6q9VliIkX+yY3jBrC/pKgRahtcIyq46Da1E6K
lc15Euur3NfGow+nott0Z8XutpYdK/2vBKcIh9JOdkd+oe6pcIP6hnhHRp53wqmG
-----END PKCS7-----`

var FirefoxAddonRootCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIGYTCCBEmgAwIBAgIBATANBgkqhkiG9w0BAQwFADB9MQswCQYDVQQGEwJVUzEc
MBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0GA1UECxMmTW96aWxsYSBB
TU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAdBgNVBAMTFnJvb3QtY2Et
cHJvZHVjdGlvbi1hbW8wHhcNMTUwMzE3MjI1MzU3WhcNMjUwMzE0MjI1MzU3WjB9
MQswCQYDVQQGEwJVUzEcMBoGA1UEChMTTW96aWxsYSBDb3Jwb3JhdGlvbjEvMC0G
A1UECxMmTW96aWxsYSBBTU8gUHJvZHVjdGlvbiBTaWduaW5nIFNlcnZpY2UxHzAd
BgNVBAMTFnJvb3QtY2EtcHJvZHVjdGlvbi1hbW8wggIgMA0GCSqGSIb3DQEBAQUA
A4ICDQAwggIIAoICAQC0u2HXXbrwy36+MPeKf5jgoASMfMNz7mJWBecJgvlTf4hH
JbLzMPsIUauzI9GEpLfHdZ6wzSyFOb4AM+D1mxAWhuZJ3MDAJOf3B1Rs6QorHrl8
qqlNtPGqepnpNJcLo7JsSqqE3NUm72MgqIHRgTRsqUs+7LIPGe7262U+N/T0LPYV
Le4rZ2RDHoaZhYY7a9+49mHOI/g2YFB+9yZjE+XdplT2kBgA4P8db7i7I0tIi4b0
B0N6y9MhL+CRZJyxdFe2wBykJX14LsheKsM1azHjZO56SKNrW8VAJTLkpRxCmsiT
r08fnPyDKmaeZ0BtsugicdipcZpXriIGmsZbI12q5yuwjSELdkDV6Uajo2n+2ws5
uXrP342X71WiWhC/dF5dz1LKtjBdmUkxaQMOP/uhtXEKBrZo1ounDRQx1j7+SkQ4
BEwjB3SEtr7XDWGOcOIkoJZWPACfBLC3PJCBWjTAyBlud0C5n3Cy9regAAnOIqI1
t16GU2laRh7elJ7gPRNgQgwLXeZcFxw6wvyiEcmCjOEQ6PM8UQjthOsKlszMhlKw
vjyOGDoztkqSBy/v+Asx7OW2Q7rlVfKarL0mREZdSMfoy3zTgtMVCM0vhNl6zcvf
5HNNopoEdg5yuXo2chZ1p1J+q86b0G5yJRMeT2+iOVY2EQ37tHrqUURncCy4uwIB
A6OB7TCB6jAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAWBgNVHSUBAf8E
DDAKBggrBgEFBQcDAzCBkgYDVR0jBIGKMIGHoYGBpH8wfTELMAkGA1UEBhMCVVMx
HDAaBgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xLzAtBgNVBAsTJk1vemlsbGEg
QU1PIFByb2R1Y3Rpb24gU2lnbmluZyBTZXJ2aWNlMR8wHQYDVQQDExZyb290LWNh
LXByb2R1Y3Rpb24tYW1vggEBMB0GA1UdDgQWBBSzvOpYdKvhbngqsqucIx6oYyyX
tzANBgkqhkiG9w0BAQwFAAOCAgEAaNSRYAaECAePQFyfk12kl8UPLh8hBNidP2H6
KT6O0vCVBjxmMrwr8Aqz6NL+TgdPmGRPDDLPDpDJTdWzdj7khAjxqWYhutACTew5
eWEaAzyErbKQl+duKvtThhV2p6F6YHJ2vutu4KIciOMKB8dslIqIQr90IX2Usljq
8Ttdyf+GhUmazqLtoB0GOuESEqT4unX6X7vSGu1oLV20t7t5eCnMMYD67ZBn0YIU
/cm/+pan66hHrja+NeDGF8wabJxdqKItCS3p3GN1zUGuJKrLykxqbOp/21byAGog
Z1amhz6NHUcfE6jki7sM7LHjPostU5ZWs3PEfVVgha9fZUhOrIDsyXEpCWVa3481
LlAq3GiUMKZ5DVRh9/Nvm4NwrTfB3QkQQJCwfXvO9pwnPKtISYkZUqhEqvXk5nBg
QCkDSLDjXTx39naBBGIVIqBtKKuVTla9enngdq692xX/CgO6QJVrwpqdGjebj5P8
5fNZPABzTezG3Uls5Vp+4iIWVAEDkK23cUj3c/HhE+Oo7kxfUeu5Y1ZV3qr61+6t
ZARKjbu1TuYQHf0fs+GwID8zeLc2zJL7UzcHFwwQ6Nda9OJN4uPAuC/BKaIpxCLL
26b24/tRam4SJjqpiq20lynhUrmTtt6hbG3E1Hpy3bmkt2DYnuMFwEx2gfXNcnbT
wNuvFqc=
-----END CERTIFICATE-----`)

// sign a document with openssl and verify the signature with pkcs7.
// this uses a chain of root, intermediate and signer cert, where the
// intermediate is added to the certs but the root isn't.
func TestSignWithOpenSSLAndVerify(t *testing.T) {
	content := []byte(`
A ship in port is safe,
but that's not what ships are built for.
-- Grace Hopper`)
	// write the content to a temp file
	tmpContentFile, err := ioutil.TempFile("", "TestSignWithOpenSSLAndVerify_content")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpContentFile.Name(), content, 0755)
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for _, sigalgroot := range sigalgs {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
		}
		truststore := x509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, sigalginter := range sigalgs {
			interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, sigalginter, true)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", sigalgroot, sigalginter, err)
			}
			// write the intermediate cert to a temp file
			tmpInterCertFile, err := ioutil.TempFile("", "TestSignWithOpenSSLAndVerify_intermediate")
			if err != nil {
				t.Fatal(err)
			}
			fd, err := os.OpenFile(tmpInterCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				t.Fatal(err)
			}
			pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: interCert.Certificate.Raw})
			fd.Close()
			for _, sigalgsigner := range sigalgs {
				signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalgsigner, false)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}

				// write the signer cert to a temp file
				tmpSignerCertFile, err := ioutil.TempFile("", "TestSignWithOpenSSLAndVerify_signer")
				if err != nil {
					t.Fatal(err)
				}
				fd, err = os.OpenFile(tmpSignerCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
				if err != nil {
					t.Fatal(err)
				}
				pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: signerCert.Certificate.Raw})
				fd.Close()

				// write the signer key to a temp file
				tmpSignerKeyFile, err := ioutil.TempFile("", "TestSignWithOpenSSLAndVerify_key")
				if err != nil {
					t.Fatal(err)
				}
				fd, err = os.OpenFile(tmpSignerKeyFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
				if err != nil {
					t.Fatal(err)
				}
				var derKey []byte
				priv := *signerCert.PrivateKey
				switch priv := priv.(type) {
				case *rsa.PrivateKey:
					derKey = x509.MarshalPKCS1PrivateKey(priv)
					pem.Encode(fd, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derKey})
				case *ecdsa.PrivateKey:
					derKey, err = x509.MarshalECPrivateKey(priv)
					if err != nil {
						t.Fatal(err)
					}
					pem.Encode(fd, &pem.Block{Type: "EC PRIVATE KEY", Bytes: derKey})
				}
				fd.Close()

				// write the root cert to a temp file
				tmpSignedFile, err := ioutil.TempFile("", "TestSignWithOpenSSLAndVerify_signature")
				if err != nil {
					t.Fatal(err)
				}
				// call openssl to sign the content
				opensslCMD := exec.Command("openssl", "smime", "-sign", "-nodetach",
					"-in", tmpContentFile.Name(), "-out", tmpSignedFile.Name(),
					"-signer", tmpSignerCertFile.Name(), "-inkey", tmpSignerKeyFile.Name(),
					"-certfile", tmpInterCertFile.Name(), "-outform", "PEM")
				out, err := opensslCMD.CombinedOutput()
				if err != nil {
					t.Fatalf("test %s/%s/%s: openssl command failed with %s: %s", sigalgroot, sigalginter, sigalgsigner, err, out)
				}

				// verify the signed content
				pemSignature, err := ioutil.ReadFile(tmpSignedFile.Name())
				if err != nil {
					t.Fatal(err)
				}
				derBlock, _ := pem.Decode(pemSignature)
				if derBlock == nil {
					break
				}
				p7, err := Parse(derBlock.Bytes)
				if err != nil {
					t.Fatalf("Parse encountered unexpected error: %v", err)
				}
				if err := p7.VerifyWithChain(truststore); err != nil {
					t.Fatalf("Verify failed with error: %v", err)
				}
				// Verify the certificate chain to make sure the identified root
				// is the one we expect
				ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, p7.Signers[0].IssuerAndSerialNumber)
				if ee == nil {
					t.Fatalf("No end-entity certificate found for signer")
				}
				chains, err := verifyCertChain(ee, p7.Certificates, truststore, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if len(chains) != 1 {
					t.Fatalf("Expected to find one chain, but found %d", len(chains))
				}
				if len(chains[0]) != 3 {
					t.Fatalf("Expected to find three certificates in chain, but found %d", len(chains[0]))
				}
				if chains[0][0].Subject.CommonName != "PKCS7 Test Signer Cert" {
					t.Fatalf("Expected to find EE certificate with subject 'PKCS7 Test Signer Cert', but found '%s'", chains[0][0].Subject.CommonName)
				}
				if chains[0][1].Subject.CommonName != "PKCS7 Test Intermediate Cert" {
					t.Fatalf("Expected to find intermediate certificate with subject 'PKCS7 Test Intermediate Cert', but found '%s'", chains[0][1].Subject.CommonName)
				}
				if chains[0][2].Subject.CommonName != "PKCS7 Test Root CA" {
					t.Fatalf("Expected to find root certificate with subject 'PKCS7 Test Root CA', but found '%s'", chains[0][2].Subject.CommonName)
				}
				os.Remove(tmpSignerCertFile.Name()) // clean up
				os.Remove(tmpSignerKeyFile.Name())  // clean up
			}
			os.Remove(tmpInterCertFile.Name()) // clean up
		}
	}
	os.Remove(tmpContentFile.Name()) // clean up
}

var sampleAppleAppAttestationReceiptFixture = []byte(`
-----BEGIN -----
MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0B
BwGggCSABIID6DGCBAswIwIBAgIBAQQbOFlFMjNOWlM1Ny5jb20ua2F5YWsudHJh
dmVsMIIC7gIBAwIBAQSCAuQwggLgMIICZqADAgECAgYBdNZm2hAwCgYIKoZIzj0E
AwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNV
BAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwOTI3MjAy
ODE4WhcNMjAwOTMwMjAyODE4WjCBkTFJMEcGA1UEAwxANTY3N2VhOGQyYTc0YWQ2
Y2IyYThkODZiN2UxZmJkZmM4ODRiMjJmNWVlNjEzM2MwOTg5MTE1NDMwOTc4NzY0
YTEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIElu
Yy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASVMXfBQ2n1hERgyf113lWGstIXHIbeiLJi+oIYyZj/aqNGPACJWSmRK/v5B67u
Z2bZrNNSoRrwJyoNiwerRvmdo4HqMIHnMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/
BAQDAgTwMHUGCSqGSIb3Y2QIBQRoMGakAwIBCr+JMAMCAQG/iTEDAgEAv4kyAwIB
Ab+JMwMCAQG/iTQdBBs4WUUyM05aUzU3LmNvbS5rYXlhay50cmF2ZWylBgQEc2tz
IL+JNgMCAQW/iTcDAgEAv4k5AwIBAL+JOgMCAQAwGwYJKoZIhvdjZAgHBA4wDL+K
eAgEBjE0LjAuMTAzBgkqhkiG92NkCAIEJjAkoSIEIMmvmBS106CCCA0l+C2IhciY
KtSnKp+1qGmv597EqyV9MAoGCCqGSM49BAMCA2gAMGUCMQC2xV2A+e9j96iphB6G
3Vm53fzMw+lZ/LlgKAHvZy6K3gNCnyMev8/O79TwiHFxBqcCMDwneBrN7P2REtFV
dPjdGFSqJQ1AS2VJtX31VRHZzY7FNRLqyTPqkuF9xnay6NWlYzAoAgEEAgEBBCC9
2s44kCAWK/w87A2CBCqO7rxzyw/c+bUL3gOkdjKdZjBgAgEFAgEBBFgrZVk0U1Nu
T2pkaWsrWGkzaUJTK1NrR1ZTR004NmlKeVBTYWMrbnUxdU94d2ZvVEFLbXg4U2N0
M1hyQmorenYvcE9kVUpodzJ6N3E2SDhHem8vekJtdz09MA4CAQYCAQEEBkFUVEVT
VDASAgEHAgEBBApwcm9kdWN0aW9uMCACAQwCAQEEGDIwMjAtMDktMjhUMjA6Mjg6
MTkEJy45NDJaMCACARUCAQEEGDIwMjAtMTItMjdUMjA6Mjg6MTkuOTQyWgAAAAAA
AKCAMIIDrTCCA1SgAwIBAgIQWTNWreVZgs9EQjes30UbUzAKBggqhkjOPQQDAjB8
MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0g
RzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYD
VQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yMDA1MTkxNzQ3MzFaFw0y
MTA2MTgxNzQ3MzFaMFoxNjA0BgNVBAMMLUFwcGxpY2F0aW9uIEF0dGVzdGF0aW9u
IEZyYXVkIFJlY2VpcHQgU2lnbmluZzETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkG
A1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR/6RU0bMOKe5g8k9HQ
Q1/Yq9pWcATTLFiGZVGVerR498sq+LpF9/p46sYsSeT5zcCEtQMU8QIz2pt2+kQq
K7hyo4IB2DCCAdQwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTZF/5LZ5A4S5L0
287VV4AUC489yTBDBggrBgEFBQcBAQQ3MDUwMwYIKwYBBQUHMAGGJ2h0dHA6Ly9v
Y3NwLmFwcGxlLmNvbS9vY3NwMDMtYWFpY2E1ZzEwMTCCARwGA1UdIASCARMwggEP
MIIBCwYJKoZIhvdjZAUBMIH9MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9u
IHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5j
ZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25k
aXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0
aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDUGCCsGAQUFBwIBFilodHRwOi8vd3d3
LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eTAdBgNVHQ4EFgQUaR7HD0fs
443ddTdE8+nhWmwQViUwDgYDVR0PAQH/BAQDAgeAMA8GCSqGSIb3Y2QMDwQCBQAw
CgYIKoZIzj0EAwIDRwAwRAIgJRgWXF4pnFn2hTmtXduZ9jc+9g7NCEWp/Xca1iQt
LCICIF0qmypfq6NjgWWNGED3r0gL12uhlNg0IIf01pNbtRuuMIIC+TCCAn+gAwIB
AgIQVvuD1Cv/jcM3mSO1Wq5uvTAKBggqhkjOPQQDAzBnMRswGQYDVQQDDBJBcHBs
ZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0xOTAz
MjIxNzUzMzNaFw0zNDAzMjIwMDAwMDBaMHwxMDAuBgNVBAMMJ0FwcGxlIEFwcGxp
Y2F0aW9uIEludGVncmF0aW9uIENBIDUgLSBHMTEmMCQGA1UECwwdQXBwbGUgQ2Vy
dGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNV
BAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEks5jvX2GsasoCjsc4a/7
BJSAkaz2Md+myyg1b0RL4SHlV90SjY26gnyVvkn6vjPKrs0EGfEvQyX69L6zy4N+
uqOB9zCB9DAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFLuw3qFYM4iapIqZ
3r6966/ayySrMEYGCCsGAQUFBwEBBDowODA2BggrBgEFBQcwAYYqaHR0cDovL29j
c3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJvb3RjYWczMDcGA1UdHwQwMC4wLKAq
oCiGJmh0dHA6Ly9jcmwuYXBwbGUuY29tL2FwcGxlcm9vdGNhZzMuY3JsMB0GA1Ud
DgQWBBTZF/5LZ5A4S5L0287VV4AUC489yTAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZI
hvdjZAYCAwQCBQAwCgYIKoZIzj0EAwMDaAAwZQIxAI1vpp+h4OTsW05zipJ/PXhT
mI/02h9YHsN1Sv44qEwqgxoaqg2mZG3huZPo0VVM7QIwZzsstOHoNwd3y9Xsdqga
OlU7PzVqyMXmkrDhYb6ASWnkXyupbOERAqrMYdk4t3NKMIICQzCCAcmgAwIBAgII
LcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAt
IEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEG
A1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcN
MzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAk
BgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApB
cHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjp
Lz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J
6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNC
MEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMB
Af8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY
2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3U
T82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKAAAMYIBljCC
AZICAQEwgZAwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRp
b24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhv
cml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMCEFkzVq3lWYLP
REI3rN9FG1MwDQYJYIZIAWUDBAIBBQCggZUwGAYJKoZIhvcNAQkDMQsGCSqGSIb3
DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwOTI4MjAyODIwWjAqBgkqhkiG9w0BCTQx
HTAbMA0GCWCGSAFlAwQCAQUAoQoGCCqGSM49BAMCMC8GCSqGSIb3DQEJBDEiBCDL
FFlod6+72Z/XBkt+1Gg9wc1binQgsCMpZ5A1Ge4fnjAKBggqhkjOPQQDAgRHMEUC
IQCE46Koolc/FuL29/MUK1Auqt2XUJPK2DD9aDJgbPPKBwIgbsggotsin/9j1y/Z
4pBdpYCE6+FY7zCTIp/IaUWymtYAAAAAAAA=
-----END -----`)

func TestParseSignedOctetStringWithAppleAttestation(t *testing.T) {
	decodedReceipt, _ := pem.Decode(sampleAppleAppAttestationReceiptFixture)
	p7, err := Parse(decodedReceipt.Bytes)
	if err != nil {
		t.Fatal("could not parse receipt containing compound octet string", err)
	}
	expectedContent := "3182040b3023020102020101041b38594532334e5a5335372e636f6d2e6b617961" +
		"6b2e74726176656c308202ee020103020101048202e4308202e030820266a00302010202060174d666da10" +
		"300a06082a8648ce3d040302304f3123302106035504030c1a4170706c6520417070204174746573746174" +
		"696f6e204341203131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c" +
		"69666f726e6961301e170d3230303932373230323831385a170d3230303933303230323831385a3081913149" +
		"304706035504030c4035363737656138643261373461643663623261386438366237653166626466633838346" +
		"232326635656536313333633039383931313534333039373837363461311a3018060355040b0c1141414120436" +
		"57274696669636174696f6e31133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a436" +
		"16c69666f726e69613059301306072a8648ce3d020106082a8648ce3d03010703420004953177c14369f5844460" +
		"c9fd75de5586b2d2171c86de88b262fa8218c998ff6aa3463c00895929912bfbf907aeee6766d9acd352a11af02" +
		"72a0d8b07ab46f99da381ea3081e7300c0603551d130101ff04023000300e0603551d0f0101ff0404030204f0307" +
		"506092a864886f76364080504683066a40302010abf893003020101bf893103020100bf893203020101bf8933030" +
		"20101bf89341d041b38594532334e5a5335372e636f6d2e6b6179616b2e74726176656ca5060404736b7320bf893603" +
		"020105bf893703020100bf893903020100bf893a03020100301b06092a864886f763640807040e300cbf8a780804063" +
		"1342e302e31303306092a864886f76364080204263024a1220420c9af9814b5d3a082080d25f82d8885c8982ad4a72a9fb5a8" +
		"69afe7dec4ab257d300a06082a8648ce3d0403020368003065023100b6c55d80f9ef63f7a8a9841e86dd59b9ddfcccc3e959f" +
		"cb9602801ef672e8ade03429f231ebfcfceefd4f088717106a702303c27781acdecfd9112d15574f8dd1854aa250d404b6549b5" +
		"7df55511d9cd8ec53512eac933ea92e17dc676b2e8d5a56330280201040201010420bddace389020162bfc3cec0d82042a8eee" +
		"bc73cb0fdcf9b50bde03a476329d66306002010502010104582b65593453536e4f6a64696b2b5869336942532b536b47565347" +
		"4d3836694a79505361632b6e7531754f7877666f54414b6d7838536374335872426a2b7a762f704f64554a6877327a37713648" +
		"38477a6f2f7a426d773d3d300e02010602010104064154544553543012020107020101040a70726f64756374696f6e30200201" +
		"0c0201010418323032302d30392d32385432303a32383a31392e3934325a30200201150201010418323032302d31322d3237" +
		"5432303a32383a31392e3934325a"
	if hex.EncodeToString(p7.Content) != expectedContent {
		t.Fatal("could not parse contained compound octet string content fully")
	}
}

func TestAzureAttestationSignatureValidation(t *testing.T) {
	// attested data from https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux#attested-data
	b64 := `MIIEEgYJKoZIhvcNAQcCoIIEAzCCA/8CAQExDzANBgkqhkiG9w0BAQsFADCBugYJKoZIhvcNAQcBoIGsBIGpeyJub25jZSI6IjEyMzQ1NjY3NjYiLCJwbGFuIjp7Im5hbWUiOiIiLCJwcm9kdWN0IjoiIiwicHVibGlzaGVyIjoiIn0sInRpbWVTdGFtcCI6eyJjcmVhdGVkT24iOiIxMS8yMC8xOCAyMjowNzozOSAtMDAwMCIsImV4cGlyZXNPbiI6IjExLzIwLzE4IDIyOjA4OjI0IC0wMDAwIn0sInZtSWQiOiIifaCCAj8wggI7MIIBpKADAgECAhBnxW5Kh8dslEBA0E2mIBJ0MA0GCSqGSIb3DQEBBAUAMCsxKTAnBgNVBAMTIHRlc3RzdWJkb21haW4ubWV0YWRhdGEuYXp1cmUuY29tMB4XDTE4MTEyMDIxNTc1N1oXDTE4MTIyMDIxNTc1NlowKzEpMCcGA1UEAxMgdGVzdHN1YmRvbWFpbi5tZXRhZGF0YS5henVyZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAML/tBo86ENWPzmXZ0kPkX5dY5QZ150mA8lommszE71x2sCLonzv4/UWk4H+jMMWRRwIea2CuQ5RhdWAHvKq6if4okKNt66fxm+YTVz9z0CTfCLmLT+nsdfOAsG1xZppEapC0Cd9vD6NCKyE8aYI1pliaeOnFjG0WvMY04uWz2MdAgMBAAGjYDBeMFwGA1UdAQRVMFOAENnYkHLa04Ut4Mpt7TkJFfyhLTArMSkwJwYDVQQDEyB0ZXN0c3ViZG9tYWluLm1ldGFkYXRhLmF6dXJlLmNvbYIQZ8VuSofHbJRAQNBNpiASdDANBgkqhkiG9w0BAQQFAAOBgQCLSM6aX5Bs1KHCJp4VQtxZPzXF71rVKCocHy3N9PTJQ9Fpnd+bYw2vSpQHg/AiG82WuDFpPReJvr7Pa938mZqW9HUOGjQKK2FYDTg6fXD8pkPdyghlX5boGWAMMrf7bFkup+lsT+n2tRw2wbNknO1tQ0wICtqy2VqzWwLi45RBwTGB6DCB5QIBATA/MCsxKTAnBgNVBAMTIHRlc3RzdWJkb21haW4ubWV0YWRhdGEuYXp1cmUuY29tAhBnxW5Kh8dslEBA0E2mIBJ0MA0GCSqGSIb3DQEBCwUAMA0GCSqGSIb3DQEBAQUABIGAld1BM/yYIqqv8SDE4kjQo3Ul/IKAVR8ETKcve5BAdGSNkTUooUGVniTXeuvDj5NkmazOaKZp9fEtByqqPOyw/nlXaZgOO44HDGiPUJ90xVYmfeK6p9RpJBu6kiKhnnYTelUk5u75phe5ZbMZfBhuPhXmYAdjc7Nmw97nx8NnprQ=`
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Errorf("failed decoding base64 attested data: %v", err)
	}

	p7, err := Parse(data)
	if err != nil {
		t.Errorf("failed parsing attested data: %v", err)
	}

	err = p7.Verify()
	if err != nil {
		t.Errorf("failed verifying data: %v", err)
	}
}
