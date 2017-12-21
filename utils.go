package otp

import (
	"encoding/base32"
	"math/rand"
	"time"
)

// Secret Quickly Generates a Secret of 20 characters
func Secret(isBase32 bool) string {
	const alphaNumericValues = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
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

	if isBase32 {
		return base32.StdEncoding.EncodeToString(bs)
	}

	return string(bs)
}
