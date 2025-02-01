package pkcs7

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestPKCS7_Marshal(t *testing.T) {
	content := []byte("Hello World")
	rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, x509.SHA256WithRSA, true)
	if err != nil {
		t.Fatalf("cannot generate root cert: %s", err)
	}
	truststore := x509.NewCertPool()
	truststore.AddCert(rootCert.Certificate)
	signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", rootCert, x509.SHA256WithRSA, false)
	if err != nil {
		t.Fatalf("cannot generate signer cert: %s", err)
	}
	toBeSigned, err := NewSignedData(content)
	if err != nil {
		t.Fatalf("cannot initialize signed data: %s", err)
	}

	// Set the digest to match the end entity cert
	signerDigest, _ := getDigestOIDForSignatureAlgorithm(signerCert.Certificate.SignatureAlgorithm)
	toBeSigned.SetDigestAlgorithm(signerDigest)

	if err := toBeSigned.AddSignerChain(signerCert.Certificate, *signerCert.PrivateKey, nil, SignerInfoConfig{}); err != nil {
		t.Fatalf("cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("cannot finish signing data: %s", err)
	}
	pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed})

	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("cannot parse signed data: %s", err)
	}

	marshaled, err := p7.Marshal()
	if err != nil {
		t.Fatalf("cannot marshal signed data: %s", err)
	}
	p7Reparsed, err := Parse(marshaled)
	if err != nil {
		t.Fatalf("cannot reparse signed data: %s", err)
	}
	if !bytes.Equal(p7.Content, p7Reparsed.Content) {
		t.Errorf("content was not found in the reparsed data:\n\tExpected: %s\n\tActual: %s", p7.Content, p7Reparsed.Content)
	}
	if err := p7Reparsed.VerifyWithChain(truststore); err != nil {
		t.Errorf("cannot verify reparsed data: %s", err)
	}
}
