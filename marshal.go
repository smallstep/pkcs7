package pkcs7

import "encoding/asn1"

func (p7 *PKCS7) Marshal() ([]byte, error) {
	var contentType asn1.ObjectIdentifier
	switch p7.raw.(type) {
	case signedData:
		contentType = OIDSignedData
	case envelopedData:
		contentType = OIDEnvelopedData
	case encryptedData:
		contentType = OIDEncryptedData
	default:
		return nil, ErrUnsupportedContentType
	}
	inner, err := asn1.Marshal(p7.raw)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(contentInfo{
		ContentType: contentType,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	})
}
