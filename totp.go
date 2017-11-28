package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"time"
)

// Totp is a struct holding the details for a time based hmac-sha1 otp
type Totp struct {
	secret     string
	timeBox    time.Time
	length     int
	window     int
	windowSize int
	isBase32   bool
	hasher     func() hash.Hash
}

// TotpConfig holds user friendly configurations for creating
// tokens using the NewTOTP function otherwise the Hotp
// object can be created independantly.
type TotpConfig struct {
	secret     string
	time       time.Time
	length     int
	window     int
	windowSize int
	useBase32  bool
	crypto     string
}

// NewTOTP constructor for hotp object
// func NewTOTP(secret string, timeBox time.Time, length int, window int, windowSize int, isBase32 bool, hasher func() hash.Hash) *Totp {
func NewTOTP(c *TotpConfig) *Totp {
	t := new(Totp)

	if len(c.secret) == 0 {
		t.secret = Secret(c.useBase32)
	} else {
		t.secret = c.secret
	}

	if c.time.IsZero() {
		t.timeBox = time.Now() // TODO this should be a const default value
	} else {
		t.timeBox = c.time
	}

	if c.length == 0 {
		t.length = 8 // TODO this should be a const default value
	} else {
		t.length = c.length
	}

	if c.window == 0 {
		t.window = 30
	} else {
		t.window = c.window
	}

	if c.windowSize == 0 {
		t.windowSize = 2
	} else {
		t.windowSize = c.windowSize
	}

	switch c.crypto {
	case "sha256":
		t.hasher = sha256.New
	case "sha512":
		t.hasher = sha512.New
	default:
		t.hasher = sha1.New
	}

	return t
}

// Generate Generates an TOTP
// Note: TOTP recommended length is 8 as per RFC 6238
func (t Totp) Generate() string {
	tw := int(t.timeBox.Unix()) / t.window
	h := Hotp{
		secret:   t.secret,
		count:    tw,
		length:   t.length,
		window:   t.window,
		isBase32: t.isBase32,
		hasher:   t.hasher,
	}
	return h.Generate()
}

// Check validates an TOTP
// accepts secret, time, length to generate the OTP's to validate
// an incoming OTP, and how many times to increase the validation count
func (t Totp) Check(otp string) bool {

	otpTime := t.timeBox
	// Iterate over the stepSize on both sides totalComparisons = stepSize * 2
	for i := -1 * t.windowSize; i < t.windowSize; i++ {
		t.timeBox = otpTime.Add(time.Second * time.Duration(i*t.window))

		if t.Generate() == otp {
			return true
		}
	}
	return false
}
