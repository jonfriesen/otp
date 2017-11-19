package totp

import "time"
import "github.com/jonfriesen/otp"

// Generate Generates an TOTP
// Note: TOTP recommended length is 8 as per RFC 6238
func Generate(secret string, t time.Time, length int) string {
	tw := int(t.Unix() / 30)
	return hotp.Generate(secret, tw, length)
}
