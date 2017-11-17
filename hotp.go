package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"math"
)

func hmacSha1(key []byte, input []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(input)
	return h.Sum(nil)
}

// Generate Generates an HOTP
// Note: HOTP recommended length is 6 as per RFC 4226
func Generate(secret []byte, count uint64, length int) string {

	text := make([]byte, 8)
	for i := len(text) - 1; i >= 0; i-- {
		text[i] = byte(count & 0xff)
		count = count >> 8
	}

	hash := hmacSha1(secret, text)

	// Where our slice starts (lower 4 bits as offset)
	offset := int(hash[len(hash)-1] & 0xf)

	// Get's 31 bit unsigned int from 31 bit mask
	// on the 4 bytes including the offset
	binary := ((int(hash[offset]&0x7f) << 24) |
		(int(hash[offset+1]&0xff) << 16) |
		(int(hash[offset+2]&0xff) << 8) |
		(int(hash[offset+3] & 0xff)))

	// Produces the actual OTP
	otp := binary % int(math.Pow10(length))

	result := fmt.Sprintf("%d", otp)
	for len(result) < length {
		result = "0" + result
	}

	return result
}

// Check validates an HOTP
// accepts secret, count, length to generate the OTP's to validate
// an incoming OTP, and how many times to increase the validation count
func Check(secret []byte, count uint64, length int, otp string, future int) (bool, int) {
	for i := 0; i < future; i++ {
		c := (count + uint64(i))
		if Generate(secret, c, length) == otp {
			return true, int(c)
		}
	}
	return false, 0
}
