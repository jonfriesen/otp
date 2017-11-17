package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

func hmacSha1(key []byte, input []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(input)
	return h.Sum(nil)
}

// GenerateOTP Generates an OTP
// Note: OTP recommended length is 6 as per RFC 4226
func GenerateOTP(secret []byte, count uint64, length int) string {

	// TODO calulate this instead
	digitsPower := []int{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

	text := make([]byte, 8)
	for i := len(text) - 1; i >= 0; i-- {
		text[i] = byte(count & 0xff)
		count = count >> 8
	}

	hash := hmacSha1(secret, text)

	offset := int(hash[len(hash)-1] & 0xf)

	binary := ((int(hash[offset]&0x7f) << 24) |
		(int(hash[offset+1]&0xff) << 16) |
		(int(hash[offset+2]&0xff) << 8) |
		(int(hash[offset+3] & 0xff)))

	otp := binary % digitsPower[length]

	result := fmt.Sprintf("%d", otp)
	for len(result) < length {
		result = "0" + result
	}

	return result
}
