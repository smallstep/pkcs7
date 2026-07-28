package pkcs7

import (
	"errors"
)

// Replaces all indefinite length encodings of BER object with definite ones.
// With typical cases this is enough to make the result DER-compatible.
func ber2der(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, errors.New("ber2der: input ber is empty")
	}

	var out []byte
	out, _, err := ber2derImpl(out, ber)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BER and DER length encoding.

// The only difference between BER and DER encoding is that the former supports
// indefinite encoding when the length encoding byte is 0x80 followed by
// children encoding bytes and followed by two zero bytes representing the
// children sequence sentinel. DER always requires the definite length encoding.
//
// If the length fits in 7 bits, the value is encoded directly (short definite form). Otherwise, the number of bytes to encode the length is first
// determined as floor(log256(length)) or the number of bytes in the big endian encoding. This number is added to 0x80. The length is encoded in big endian
// encoding follow after the initial byte.
//
// Examples:
//  length | byte 1 | bytes n
//  0      | 0x00   | -
//  120    | 0x78   | -
//  200    | 0x81   | 0xC8
//  500    | 0x82   | 0x01 0xF4

// Restrict the maximum supported length of BER elements to 2**31 - 1 that
// corresponds to max 4 bytes of length encoding bits.
const maxLengthOctetCount = 4

// Get number of bytes in the long length encoding
func derLongLengthEncodingSpan(length int) int {
	if length < 0x80 {
		if length < 0 {
			panic("negative length")
		} else {
			panic("this should not be called for the short length")
		}
	}
	lengthSpan := 0
	for {
		lengthSpan++
		length >>= 8
		if length == 0 {
			return lengthSpan
		}
	}
}

func encodeLength(out []byte, length int) []byte {
	if length < 0x80 {
		return append(out, byte(length))
	}
	lengthSpan := derLongLengthEncodingSpan(length)
	out = append(out, 0x80|byte(lengthSpan))
	for i := lengthSpan; i > 0; i-- {
		out = append(out, byte(length>>uint((i-1)*8)))
	}
	return out
}

func ber2derImpl(
	out []byte, ber []byte,
) ([]byte, int, error) {
	if len(ber) == 0 {
		return nil, 0, errors.New("ber2der: empty BER object")
	}
	b := ber[0]
	offset := 1
	if offset >= len(ber) {
		return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	tag := b & 0x1F // last 5 bits
	if tag == 0x1F {
		tag = 0
		for ber[offset] >= 0x80 {
			tag = tag*128 + ber[offset] - 0x80
			offset++
			if offset > len(ber) {
				return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
		}
		// jvehent 20170227: this doesn't appear to be used anywhere...
		// tag = tag*128 + ber[offset] - 0x80
		offset++
		if offset > len(ber) {
			return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
		}
	}
	// Append the BER tag
	out = append(out, ber[0:offset]...)

	isConstructed := (b & 0x20) != 0

	// read length
	var length int
	l := ber[offset]
	offset++
	if offset > len(ber) {
		return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	indefinite := false
	if l > 0x80 {
		// Long definite encoding.
		numberOfBytes := int(l & 0x7F)
		if numberOfBytes > maxLengthOctetCount {
			return nil, 0, errors.New("ber2der: BER tag length too long")
		}
		if numberOfBytes == maxLengthOctetCount && int(ber[offset]) > 0x7F {
			return nil, 0, errors.New("ber2der: BER tag length is negative")
		}
		if int(ber[offset]) == 0x0 {
			return nil, 0, errors.New("ber2der: BER tag length has leading zero")
		}
		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + int(ber[offset])
			offset++
			if offset > len(ber) {
				return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
		}
		if length < 0 {
			return nil, 0, errors.New("ber2der: invalid negative value found in BER tag length")
		}
	} else if l == 0x80 {
		// Keep length at 0
		indefinite = true
	} else {
		length = (int)(l)
	}

	var contentEnd int
	if !indefinite {
		// Do length + offset only after it is known that the sum does not
		// overflow int32.
		if length > len(ber)-offset {
			return nil, 0, errors.New("ber2der: BER tag length is more than available data")
		}
		contentEnd = offset + length
	}

	if !isConstructed {
		if indefinite {
			return nil, 0, errors.New("ber2der: Indefinite form tag must have constructed encoding")
		}
		out = encodeLength(out, length)
		out = append(out, ber[offset:contentEnd]...)
		return out, contentEnd, nil
	}

	// Reserve one byte for the length. If the real length encoding will take
	// more space, the code below will move the children as necessary.
	lengthWriteOffset := len(out)
	out = append(out, 0)

	for indefinite || (offset != contentEnd) {
		var err error
		var n int
		out, n, err = ber2derImpl(out, ber[offset:])
		if err != nil {
			return nil, 0, err
		}
		// This cannot overflow as offset + n is bound by len(ber).
		offset += n
		if indefinite {
			if len(ber)-2 < offset {
				return nil, 0, errors.New("ber2der: Invalid BER format")
			}
			terminated := ber[offset] == 0 && ber[offset+1] == 0
			if terminated {
				offset += 2
				break
			}
		} else if offset > contentEnd {
			return nil, 0, errors.New(
				"ber2der: a nested object spans beyond parent's length")
		}
	}

	writtenLength := len(out) - (lengthWriteOffset + 1)
	if writtenLength < 0x80 {
		// The length encoding is the length itself, just write the value into
		// the reserved byte.
		out[lengthWriteOffset] = byte(writtenLength)
	} else {
		// The length encoding takes 1 + log256(length) bytes, expand the result
		// as necessary.
		lengthEncodingSpan := derLongLengthEncodingSpan(writtenLength)
		// Reserve space for the length.
		for i := 0; i < lengthEncodingSpan; i++ {
			out = append(out, 0)
		}
		tail := out[lengthWriteOffset:]
		// Make hole for the length
		copy(tail[1+lengthEncodingSpan:], tail[1:])
		_ = encodeLength(tail[:0], writtenLength)
	}

	return out, offset, nil
}
