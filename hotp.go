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
	Secret   string
	Count    int
	Length   int
	Window   int
	IsBase32 bool
	Hasher   func() hash.Hash
}

// HotpConfig holds user friendly configurations for creating
// tokens using the NewHOTP function otherwise the Hotp
// object can be created independantly.
type HotpConfig struct {
	Secret    string
	Count     int
	Length    int
	Window    int
	UseBase32 bool
	Crypto    string
}

// NewHOTP constructor for hotp object
func NewHOTP(c *HotpConfig) *Hotp {
	h := new(Hotp)

	if len(c.Secret) == 0 {
		h.Secret = Secret(c.UseBase32)
	} else {
		h.Secret = c.Secret
	}

	if c.Count == 0 {
		h.Count = 0 // TODO this should be a const default value
	} else {
		h.Count = c.Count
	}

	if c.Length == 0 {
		h.Length = 6 // TODO this should be a const default value
	} else {
		h.Length = c.Length
	}

	if c.Window == 0 {
		h.Window = 5
	} else {
		h.Window = c.Window
	}

	h.IsBase32 = c.UseBase32

	switch c.Crypto {
	case "sha256":
		h.Hasher = sha256.New
	case "sha512":
		h.Hasher = sha512.New
	default:
		h.Hasher = sha1.New
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
		text[i] = byte(h.Count & 0xff)
		h.Count = h.Count >> 8
	}

	var hash []byte
	if h.IsBase32 {
		decodedSecret, _ := base32.StdEncoding.DecodeString(h.Secret)
		hash = hmacSha(string(decodedSecret), text, h.Hasher)
	} else {
		hash = hmacSha(h.Secret, text, h.Hasher)
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
	otp := binary % int(math.Pow10(h.Length))

	result := fmt.Sprintf("%d", otp)
	for len(result) < h.Length {
		result = "0" + result
	}

	return result
}

// Check validates an HOTP
// accepts secret, count, length to generate the OTP's to validate
// an incoming OTP, and how many times to increase the validation count
func (h Hotp) Check(otp string) (bool, int) {
	for i := 0; i < h.Window; i++ {
		o := h.Generate()
		if o == otp {
			return true, int(h.Count)
		}
		h.Count++
	}
	return false, 0
}

// Sync checks next OTP until it finds two sequential matches
// max of 100 checks returns success and new count location
func (h Hotp) Sync(otp1 string, otp2 string) (bool, int) {

	h.Window = 100

	v, i := h.Check(otp1)

	// return false if no match is found
	if !v {
		return false, 0
	}

	// check second otp if first was succesful
	h.Count = h.Count + i + 1
	h.Window = 1
	v2, i2 := h.Check(otp2)
	if v2 {
		// the new location of the count
		return true, i2 + 1
	}

	// return false if second check fails
	return false, 0

}
