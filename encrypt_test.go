package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestEncrypt(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128CBC,
		EncryptionAlgorithmAES256CBC,
		EncryptionAlgorithmAES128GCM,
		EncryptionAlgorithmAES256GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
	}
	for _, mode := range modes {
		for _, sigalg := range sigalgs {
			ContentEncryptionAlgorithm = mode

			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestEncryptUsingPSK(t *testing.T) {
	modes := []int{
		EncryptionAlgorithmDESCBC,
		EncryptionAlgorithmAES128GCM,
	}

	for _, mode := range modes {
		ContentEncryptionAlgorithm = mode
		plaintext := []byte("Hello Secret World!")
		var key []byte

		switch mode {
		case EncryptionAlgorithmDESCBC:
			key = []byte("64BitKey")
		case EncryptionAlgorithmAES128GCM:
			key = []byte("128BitKey4AESGCM")
		}
		ciphertext, err := EncryptUsingPSK(plaintext, key)
		if err != nil {
			t.Fatal(err)
		}

		p7, _ := Parse(ciphertext)
		result, err := p7.DecryptUsingPSK(key)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		if !bytes.Equal(plaintext, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}

func TestPad(t *testing.T) {
	tests := []struct {
		Original  []byte
		Expected  []byte
		BlockSize int
	}{
		{[]byte{0x1, 0x2, 0x3, 0x10}, []byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4}, 8},
		{[]byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8}, 8},
	}
	for _, test := range tests {
		padded, err := pad(test.Original, test.BlockSize)
		if err != nil {
			t.Errorf("pad encountered error: %s", err)
			continue
		}
		if !bytes.Equal(test.Expected, padded) {
			t.Errorf("pad results mismatch:\n\tExpected: %X\n\tActual: %X", test.Expected, padded)
		}
	}
}

func Test_getParametersForKeyEncryptionAlgorithm(t *testing.T) {
	type args struct {
		algorithm asn1.ObjectIdentifier
		hash      crypto.Hash
	}
	tests := []struct {
		name   string
		args   args
		expErr error
	}{
		{name: "sha256", args: args{algorithm: OIDEncryptionAlgorithmRSAESOAEP, hash: crypto.SHA256}},
		{name: "sha512", args: args{algorithm: OIDEncryptionAlgorithmRSAESOAEP, hash: crypto.SHA512}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getParametersForKeyEncryptionAlgorithm(tt.args.algorithm, tt.args.hash)
			if tt.expErr != nil {
				if err == nil {
					t.Errorf("getParametersForKeyEncryptionAlgorithm() error = %v, expErr %v", err, tt.expErr)
					return
				}
				if err.Error() != tt.expErr.Error() {
					t.Errorf("getParametersForKeyEncryptionAlgorithm() = %v, want %v", err.Error(), tt.expErr.Error())
					return
				}
			}

			// test if the reverse operation results in the same value
			alg := pkix.AlgorithmIdentifier{Algorithm: tt.args.algorithm, Parameters: got}
			resultHash, err := getHashFuncForKeyEncryptionAlgorithm(alg)
			if err != nil {
				t.Errorf("getHashFuncForKeyEncryptionAlgorithm errors = %v", err)
			}

			if resultHash != tt.args.hash {
				t.Errorf("getHashFuncForKeyEncryptionAlgorithm() = %v, want %v", resultHash, tt.args.hash)
			}
		})
	}
}
