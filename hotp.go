package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"fmt"
	"hash"
	"math"
)

// Hotp is a struct holding the details for a hmac-sha1 otp
type Hotp struct {
	secret   string
	count    int
	length   int
	window   int
	isBase32 bool
	hasher   func() hash.Hash
}

// HotpConfig holds user friendly configurations for creating
// tokens using the NewHOTP function otherwise the Hotp
// object can be created independantly.
type HotpConfig struct {
	secret    string
	count     int
	length    int
	window    int
	useBase32 bool
	crypto    string
}

// NewHOTP constructor for hotp object
func NewHOTP(c *HotpConfig) *Hotp {
	h := new(Hotp)

	if len(c.secret) == 0 {
		h.secret = Secret(c.useBase32)
	} else {
		h.secret = c.secret
	}

	if c.count == 0 {
		h.count = 0 // TODO this should be a const default value
	} else {
		h.count = c.count
	}

	if c.length == 0 {
		h.length = 6 // TODO this should be a const default value
	} else {
		h.length = c.length
	}

	if c.window == 0 {
		h.window = 5
	} else {
		h.window = c.window
	}

	switch c.crypto {
	case "sha256":
		h.hasher = sha256.New
	case "sha512":
		h.hasher = sha512.New
	default:
		h.hasher = sha1.New
	}

	return h
}

func hmacSha(key string, input []byte, hasher func() hash.Hash) []byte {
	h := hmac.New(hasher, []byte(key))
	h.Write(input)
	return h.Sum(nil)
}

// Generate Generates an HOTP
// Note: HOTP recommended length is 6 as per RFC 4226
func (h Hotp) Generate() string {

	text := make([]byte, 8)
	for i := len(text) - 1; i >= 0; i-- {
		text[i] = byte(h.count & 0xff)
		h.count = h.count >> 8
	}

	var hash []byte
	if h.isBase32 {
		decodedSecret, _ := base32.StdEncoding.DecodeString(h.secret)
		hash = hmacSha(string(decodedSecret), text, h.hasher)
	} else {
		hash = hmacSha(h.secret, text, h.hasher)
	}

	// Where our slice starts (lower 4 bits as offset)
	offset := int(hash[len(hash)-1] & 0xf)

	// Get's 31 bit unsigned int from 31 bit mask
	// on the 4 bytes including the offset
	binary := ((int(hash[offset]&0x7f) << 24) |
		(int(hash[offset+1]&0xff) << 16) |
		(int(hash[offset+2]&0xff) << 8) |
		(int(hash[offset+3] & 0xff)))

	// Produces the actual OTP
	otp := binary % int(math.Pow10(h.length))

	result := fmt.Sprintf("%d", otp)
	for len(result) < h.length {
		result = "0" + result
	}

	return result
}

// Check validates an HOTP
// accepts secret, count, length to generate the OTP's to validate
// an incoming OTP, and how many times to increase the validation count
func (h Hotp) Check(otp string) (bool, int) {
	for i := 0; i < h.window; i++ {
		o := h.Generate()
		if o == otp {
			return true, int(h.count)
		}
		h.count++
	}
	return false, 0
}

// Sync checks next OTP until it finds two sequential matches
// max of 100 checks returns success and new count location
func (h Hotp) Sync(otp1 string, otp2 string) (bool, int) {

	h.window = 100

	v, i := h.Check(otp1)

	// return false if no match is found
	if !v {
		return false, 0
	}

	// check second otp if first was succesful
	h.count = h.count + i + 1
	h.window = 1
	v2, i2 := h.Check(otp2)
	if v2 {
		// the new location of the count
		return true, i2 + 1
	}

	// return false if second check fails
	return false, 0

}
