//go:build !go1.16
// +build !go1.16

// Support for DSA was deprecated in Go 1.16, so the tests in this file will only be
// executed when a Go version below that is used. Also see https://github.com/golang/go/issues/4033.

package pkcs7

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
)

func TestVerifyEC2(t *testing.T) {
	fixture := UnmarshalDSATestFixture(EC2IdentityDocumentFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	p7.Certificates = []*x509.Certificate{fixture.Certificate}
	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

var EC2IdentityDocumentFixture = `
-----BEGIN PKCS7-----
MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCA
JIAEggGmewogICJwcml2YXRlSXAiIDogIjE3Mi4zMC4wLjI1MiIsCiAgImRldnBh
eVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJhdmFpbGFiaWxpdHlab25lIiA6ICJ1
cy1lYXN0LTFhIiwKICAidmVyc2lvbiIgOiAiMjAxMC0wOC0zMSIsCiAgImluc3Rh
bmNlSWQiIDogImktZjc5ZmU1NmMiLAogICJiaWxsaW5nUHJvZHVjdHMiIDogbnVs
bCwKICAiaW5zdGFuY2VUeXBlIiA6ICJ0Mi5taWNybyIsCiAgImFjY291bnRJZCIg
OiAiMTIxNjU5MDE0MzM0IiwKICAiaW1hZ2VJZCIgOiAiYW1pLWZjZTNjNjk2IiwK
ICAicGVuZGluZ1RpbWUiIDogIjIwMTYtMDQtMDhUMDM6MDE6MzhaIiwKICAiYXJj
aGl0ZWN0dXJlIiA6ICJ4ODZfNjQiLAogICJrZXJuZWxJZCIgOiBudWxsLAogICJy
YW1kaXNrSWQiIDogbnVsbCwKICAicmVnaW9uIiA6ICJ1cy1lYXN0LTEiCn0AAAAA
AAAxggEYMIIBFAIBATBpMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5n
dG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2Vi
IFNlcnZpY2VzIExMQwIJAJa6SNnlXhpnMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0B
CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjA0MDgwMzAxNDRaMCMG
CSqGSIb3DQEJBDEWBBTuUc28eBXmImAautC+wOjqcFCBVjAJBgcqhkjOOAQDBC8w
LQIVAKA54NxGHWWCz5InboDmY/GHs33nAhQ6O/ZI86NwjA9Vz3RNMUJrUPU5tAAA
AAAAAA==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----`

func TestDSASignWithOpenSSLAndVerify(t *testing.T) {
	content := []byte(`
A ship in port is safe,
but that's not what ships are built for.
-- Grace Hopper`)
	// write the content to a temp file
	tmpContentFile, err := ioutil.TempFile("", "TestDSASignWithOpenSSLAndVerify_content")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpContentFile.Name(), content, 0755)

	// write the signer cert to a temp file
	tmpSignerCertFile, err := ioutil.TempFile("", "TestDSASignWithOpenSSLAndVerify_signer")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpSignerCertFile.Name(), dsaPublicCert, 0755)

	// write the signer key to a temp file
	tmpSignerKeyFile, err := ioutil.TempFile("", "TestDSASignWithOpenSSLAndVerify_key")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpSignerKeyFile.Name(), dsaPrivateKey, 0755)

	tmpSignedFile, err := ioutil.TempFile("", "TestDSASignWithOpenSSLAndVerify_signature")
	if err != nil {
		t.Fatal(err)
	}
	// call openssl to sign the content
	opensslCMD := exec.Command("openssl", "smime", "-sign", "-nodetach", "-md", "sha1",
		"-in", tmpContentFile.Name(), "-out", tmpSignedFile.Name(),
		"-signer", tmpSignerCertFile.Name(), "-inkey", tmpSignerKeyFile.Name(),
		"-certfile", tmpSignerCertFile.Name(), "-outform", "PEM")
	out, err := opensslCMD.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl command failed with %s: %s", err, out)
	}

	// verify the signed content
	pemSignature, err := ioutil.ReadFile(tmpSignedFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s\n", pemSignature)
	derBlock, _ := pem.Decode(pemSignature)
	if derBlock == nil {
		t.Fatalf("failed to read DER block from signature PEM %s", tmpSignedFile.Name())
	}
	p7, err := Parse(derBlock.Bytes)
	if err != nil {
		t.Fatalf("Parse encountered unexpected error: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("Verify failed with error: %v", err)
	}
	os.Remove(tmpSignerCertFile.Name()) // clean up
	os.Remove(tmpSignerKeyFile.Name())  // clean up
	os.Remove(tmpContentFile.Name())    // clean up
}

var dsaPrivateKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdS
PO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVCl
pJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith
1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7L
vKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3
zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImo
g9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUfW4aPdQBn9gJZp2KuNpzgHzvfsE=
-----END PRIVATE KEY-----`)

type DSATestFixture struct {
	Input       []byte
	Certificate *x509.Certificate
}

func UnmarshalDSATestFixture(testPEMBlock string) DSATestFixture {
	var result DSATestFixture
	var derBlock *pem.Block
	var pemBlock = []byte(testPEMBlock)
	for {
		derBlock, pemBlock = pem.Decode(pemBlock)
		if derBlock == nil {
			break
		}
		switch derBlock.Type {
		case "PKCS7":
			result.Input = derBlock.Bytes
		case "CERTIFICATE":
			result.Certificate, _ = x509.ParseCertificate(derBlock.Bytes)
		}
	}

	return result
}
