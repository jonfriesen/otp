package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"math"
	"math/rand"
	"time"
)

func hmacSha1(key string, input []byte) []byte {
	h := hmac.New(sha1.New, []byte(key))
	h.Write(input)
	return h.Sum(nil)
}

// Generate Generates an HOTP
// Note: HOTP recommended length is 6 as per RFC 4226
func Generate(secret string, count int, length int) string {

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
func Check(secret string, count int, length int, otp string, future int) (bool, int) {
	for i := 0; i < future; i++ {
		c := count + i
		if Generate(secret, c, length) == otp {
			return true, int(c)
		}
	}
	return false, 0
}

// Sync checks next OTP until it finds two sequential matches
// max of 100 checks returns success and new count location
func Sync(secret string, count int, length int, otp1 string, otp2 string) (bool, int) {
	v, i := Check(secret, count, length, otp1, 100)

	// return false if no match is found
	if !v {
		return false, 0
	}

	// check second otp if first was succesful
	v2, i2 := Check(secret, (count + i + 1), length, otp2, 1)
	if v2 {
		return true, int(count + i2)
	}

	// return false if second check fails
	return false, 0

}

// Secret Quickly Generates a Secret of 20 characters
func Secret() string {
	const alphaNumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	const length = 20
	const (
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	)

	rng := rand.NewSource(time.Now().UnixNano())

	bs := make([]byte, length)

	for i, c, r := length-1, rng.Int63(), letterIdxMax; i >= 0; {
		if r == 0 {
			c, r = rng.Int63(), letterIdxMax
		}
		if idx := int(c & letterIdxMask); idx < len(alphaNumeric) {
			bs[i] = alphaNumeric[idx]
			i--
		}
		c = c >> letterIdxBits
		r--
	}

	return string(bs)
}
