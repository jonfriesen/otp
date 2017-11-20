package totp

import "time"
import "github.com/jonfriesen/otp"

const defaultStep int64 = 30

// Generate Generates an TOTP
// Note: TOTP recommended length is 8 as per RFC 6238
func Generate(secret string, t time.Time, length int) string {
	tw := int(t.Unix() / defaultStep)
	return hotp.Generate(secret, tw, length)
}

// Check validates an TOTP
// accepts secret, time, length to generate the OTP's to validate
// an incoming OTP, and how many times to increase the validation count
func Check(secret string, t time.Time, length int, otp string) bool {
	// This is the size on either side of the time that
	// valid tokens will be accepted
	windowStepSize := 2
	windowStep := 30

	// Iterate over the stepSize on both sides totalComparisons = stepSize * 2
	for i := -1 * windowStepSize; i < windowStepSize; i++ {
		nt := t.Add(time.Second * time.Duration(i*windowStep))
		if Generate(secret, nt, length) == otp {
			return true
		}
	}
	return false
}
