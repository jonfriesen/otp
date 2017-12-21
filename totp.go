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
	Secret     string
	TimeBox    time.Time
	Length     int
	Window     int
	WindowSize int
	IsBase32   bool
	Hasher     func() hash.Hash
}

// TotpConfig holds user friendly configurations for creating
// tokens using the NewTOTP function otherwise the Hotp
// object can be created independantly.
type TotpConfig struct {
	Secret     string
	Time       time.Time
	Length     int
	Window     int
	WindowSize int
	UseBase32  bool
	Crypto     string
}

// NewTOTP constructor for hotp object
// func NewTOTP(secret string, TimeBox time.Time, length int, window int, windowSize int, isBase32 bool, hasher func() hash.Hash) *Totp {
func NewTOTP(c *TotpConfig) *Totp {
	t := new(Totp)

	if len(c.Secret) == 0 {
		t.Secret = Secret(c.UseBase32)
	} else {
		t.Secret = c.Secret
	}

	if c.Time.IsZero() {
		t.TimeBox = time.Now() // TODO this should be a const default value
	} else {
		t.TimeBox = c.Time
	}

	if c.Length == 0 {
		t.Length = 8 // TODO this should be a const default value
	} else {
		t.Length = c.Length
	}

	if c.Window == 0 {
		t.Window = 30
	} else {
		t.Window = c.Window
	}

	if c.WindowSize == 0 {
		t.WindowSize = 2
	} else {
		t.WindowSize = c.WindowSize
	}

	t.IsBase32 = c.UseBase32

	switch c.Crypto {
	case "sha256":
		t.Hasher = sha256.New
	case "sha512":
		t.Hasher = sha512.New
	default:
		t.Hasher = sha1.New
	}

	return t
}

// Generate Generates an TOTP
// Note: TOTP recommended length is 8 as per RFC 6238
func (t Totp) Generate() string {
	tw := int(t.TimeBox.Unix()) / t.Window
	h := Hotp{
		Secret:   t.Secret,
		Count:    tw,
		Length:   t.Length,
		Window:   t.Window,
		IsBase32: t.IsBase32,
		Hasher:   t.Hasher,
	}
	return h.Generate()
}

// Check validates an TOTP
// accepts secret, time, length to generate the OTP's to validate
// an incoming OTP, and how many times to increase the validation count
func (t Totp) Check(otp string) bool {

	otpTime := t.TimeBox
	// Iterate over the stepSize on both sides totalComparisons = stepSize * 2
	for i := -1 * t.WindowSize; i < t.WindowSize; i++ {
		t.TimeBox = otpTime.Add(time.Second * time.Duration(i*t.Window))

		if t.Generate() == otp {
			return true
		}
	}
	return false
}
