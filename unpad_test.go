package pkcs7

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"testing"
)

// mustMarshal marshals value to DER, failing the test if it cannot.
func mustMarshal(t *testing.T, value interface{}) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// buildEncryptedMessage marshals an encryptedContentInfo into a CMS message
// that Parse accepts: encryptedData when enveloped is false, which is read
// back with DecryptUsingPSK, or envelopedData when it is true, which is read
// back with Decrypt and the recipient certificate.
func buildEncryptedMessage(t *testing.T, eci encryptedContentInfo, cert *x509.Certificate, wrappedKey []byte, enveloped bool) []byte {
	t.Helper()
	contentType := OIDEncryptedData
	inner := mustMarshal(t, encryptedData{Version: 0, EncryptedContentInfo: eci})
	if enveloped {
		contentType = OIDEnvelopedData
		inner = mustMarshal(t, envelopedData{
			Version: 0,
			RecipientInfos: []recipientInfo{{
				Version: 0,
				IssuerAndSerialNumber: issuerAndSerial{
					IssuerName:   asn1.RawValue{FullBytes: cert.RawIssuer},
					SerialNumber: cert.SerialNumber,
				},
				KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmRSA, Parameters: asn1.NullRawValue},
				EncryptedKey:           wrappedKey,
			}},
			EncryptedContentInfo: eci,
		})
	}
	return mustMarshal(t, contentInfo{ContentType: contentType, Content: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner}})
}

func TestUnpad(t *testing.T) {
	for _, blockSize := range []int{8, 16} {
		t.Run(fmt.Sprint(blockSize), func(t *testing.T) {
			for _, tt := range []struct {
				name    string
				data    []byte
				want    []byte
				wantErr bool
			}{
				{"empty", nil, nil, true},
				{"unaligned", make([]byte, blockSize-1), nil, true},
				{"zero-padding", make([]byte, blockSize), nil, true},
				{"padding-exceeds-input", bytes.Repeat([]byte{255}, blockSize), nil, true},
				{"padding-exceeds-block", bytes.Repeat([]byte{byte(blockSize + 1)}, 2*blockSize), nil, true},
				{"inconsistent-padding", append(make([]byte, blockSize-1), 2), nil, true},
				{"one-byte-padding", append(make([]byte, blockSize-1), 1), make([]byte, blockSize-1), false},
				{"full-block-padding", bytes.Repeat([]byte{byte(blockSize)}, blockSize), []byte{}, false},
			} {
				t.Run(tt.name, func(t *testing.T) {
					got, err := unpad(tt.data, blockSize)
					if (err != nil) != tt.wantErr {
						t.Fatalf("unpad error = %v, want error %v", err, tt.wantErr)
					}
					if !bytes.Equal(got, tt.want) {
						t.Errorf("unpad = %x, want %x", got, tt.want)
					}
				})
			}
		})
	}
	for _, blockSize := range []int{0, -1} {
		if _, err := unpad([]byte{1}, blockSize); err == nil {
			t.Errorf("unpad with block size %d: expected error", blockSize)
		}
	}
}

// Exercise both exported decryption methods after parsing a serialized message.
// Building an envelope requires only the recipient's public certificate.
func TestDecryptPadding(t *testing.T) {
	fixture := UnmarshalTestFixture(EncryptedTestFixture)
	key := make([]byte, 16) // Fixed test key and IV; never used outside this test.
	iv := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	wrappedKey, err := rsa.EncryptPKCS1v15(rand.Reader, fixture.Certificate.PublicKey.(*rsa.PublicKey), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		last    byte
		wantErr bool
	}{
		{"valid", 1, false},
		{"oversized", 255, true},
		{"zero", 0, true},
	} {
		plaintext := make([]byte, aes.BlockSize)
		plaintext[len(plaintext)-1] = tt.last
		ciphertext := make([]byte, len(plaintext))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
		eci := encryptedContentInfo{
			ContentType: OIDData,
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  OIDEncryptionAlgorithmAES128CBC,
				Parameters: asn1.RawValue{FullBytes: mustMarshal(t, iv)},
			},
			EncryptedContent: asn1.RawValue{Class: 2, Tag: 0, Bytes: ciphertext},
		}
		for _, enveloped := range []bool{false, true} {
			name := "PSK/" + tt.name
			if enveloped {
				name = "RSA/" + tt.name
			}
			t.Run(name, func(t *testing.T) {
				der := buildEncryptedMessage(t, eci, fixture.Certificate, wrappedKey, enveloped)
				p7, err := Parse(der)
				if err != nil {
					t.Fatal(err)
				}
				var got []byte
				if enveloped {
					got, err = p7.Decrypt(fixture.Certificate, fixture.PrivateKey)
				} else {
					got, err = p7.DecryptUsingPSK(key)
				}
				if tt.wantErr {
					if err == nil || err.Error() != "pkcs7: invalid padding" {
						t.Fatalf("expected invalid padding error, got %v", err)
					}
					if got != nil {
						t.Errorf("expected no plaintext, got %x", got)
					}
				} else if err != nil || !bytes.Equal(got, plaintext[:len(plaintext)-1]) {
					t.Fatalf("valid padding: got %x, error %v", got, err)
				}
			})
		}
	}
}
