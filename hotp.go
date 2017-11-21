package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// Hotp is a struct holding the details for a hmac-sha1 otp
type Hotp struct {
	secret string
	count  int
	length int
	window int
}

// NewHOTP constructor for hotp object
func NewHOTP(secret string, count int, length int, window int) *Hotp {
	h := new(Hotp)

	if len(secret) == 0 {
		h.secret = Secret()
	} else {
		h.secret = secret
	}

	if count == 0 {
		h.count = 0 // TODO this should be a const default value
	} else {
		h.count = count
	}

	if length == 0 {
		h.length = 6 // TODO this should be a const default value
	} else {
		h.length = length
	}

	if window == 0 {
		h.window = 5
	} else {
		h.window = window
	}

	return h
}

func hmacSha1(key string, input []byte) []byte {
	h := hmac.New(sha1.New, []byte(key))
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

	hash := hmacSha1(h.secret, text)

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

// Secret Quickly Generates a Secret of 20 characters
func Secret() string {
	const alphaNumericValues = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	const length = 20
	const (
		idBits = 6             // 6 bits to represent a letter index
		idMask = 1<<idBits - 1 // All 1-bits, as many as idBits
		idMax  = 63 / idBits   // # of letter indices fitting in 63 bits
	)

	rng := rand.NewSource(time.Now().UnixNano())

	bs := make([]byte, length)

	for i, c, r := length-1, rng.Int63(), idMax; i >= 0; {
		if r == 0 {
			c, r = rng.Int63(), idMax
		}
		if id := int(c & idMask); id < len(alphaNumericValues) {
			bs[i] = alphaNumericValues[id]
			i--
		}
		c = c >> idBits
		r--
	}

	return string(bs)
}
