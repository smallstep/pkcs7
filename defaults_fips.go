//go:build requirefips
// +build requirefips

package pkcs7

import "crypto"

const (
	// EncryptionAlgorithmDESCBC is the DES CBC encryption algorithm
	EncryptionAlgorithmDESCBC = iota

	// EncryptionAlgorithmAES128CBC is the AES 128 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES128CBC

	// EncryptionAlgorithmAES256CBC is the AES 256 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES256CBC

	// EncryptionAlgorithmAES128GCM is the AES 128 bits with GCM encryption algorithm
	EncryptionAlgorithmAES128GCM

	// EncryptionAlgorithmAES256GCM is the AES 256 bits with GCM encryption algorithm
	EncryptionAlgorithmAES256GCM
)

// ContentEncryptionAlgorithm determines the algorithm used to encrypt the
// plaintext message. Change the value of this variable to change which
// algorithm is used in the Encrypt() function.
var ContentEncryptionAlgorithm = EncryptionAlgorithmDESCBC

// KeyEncryptionHash determines the crypto.Hash algorithm to use
// when encrypting a content key. Change the value of this variable
// to change which algorithm is used in the Encrypt() function.
var KeyEncryptionHash = crypto.SHA256

// KeyEncryptionAlgorithm determines the algorithm used to encrypt a
// content key. Change the value of this variable to change which
// algorithm is used in the Encrypt() function.
var KeyEncryptionAlgorithm = OIDEncryptionAlgorithmRSA

// SignatureAlgorithm determines the algorithm used to sign the message.
// Change the value of this variable to change which algorithm is used in
// the PKCS7 Envelope signing
var SignatureDigestAlgorithm = OIDDigestAlgorithmSHA1
