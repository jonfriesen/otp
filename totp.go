package otp

import "time"

// Totp is a struct holding the details for a time based hmac-sha1 otp
type Totp struct {
	secret     string
	timeBox    time.Time
	length     int
	window     int
	windowSize int
	isBase32   bool
}

// NewTOTP constructor for hotp object
func NewTOTP(secret string, timeBox time.Time, length int, window int, windowSize int, isBase32 bool) *Totp {
	t := new(Totp)

	if len(secret) == 0 {
		t.secret = Secret(isBase32)
	} else {
		t.secret = secret
	}

	if timeBox.IsZero() {
		t.timeBox = time.Now() // TODO this should be a const default value
	} else {
		t.timeBox = timeBox
	}

	if length == 0 {
		t.length = 8 // TODO this should be a const default value
	} else {
		t.length = length
	}

	if window == 0 {
		t.window = 30
	} else {
		t.window = window
	}

	if windowSize == 0 {
		t.windowSize = 2
	} else {
		t.windowSize = windowSize
	}

	return t
}

// Generate Generates an TOTP
// Note: TOTP recommended length is 8 as per RFC 6238
func (t Totp) Generate() string {
	tw := int(t.timeBox.Unix()) / t.window
	h := NewHOTP(t.secret, tw, t.length, t.window, t.isBase32)
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
