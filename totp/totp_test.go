package totp

import (
	"testing"
	"time"
)

const (
	defaultSecret string = "12345678901234567890"
	defaultLength int    = 8
)

func TestGenerate(t *testing.T) {
	tm := time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC)
	eOtp := "94287082"
	rOtp := Generate(defaultSecret, tm, defaultLength)

	if rOtp != eOtp {
		t.Errorf("Expected %v but got %v", eOtp, rOtp)
	}
}

func TestCheck(t *testing.T) {
	tm := time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC)
	eOtp := "94287082"

	isValid := Check(defaultSecret, tm, defaultLength, eOtp)
	if !isValid {
		t.Errorf("Expected %v to be valid but was %v", eOtp, isValid)
	}

	isValid = Check(defaultSecret, tm, defaultLength, "12345678")
	if isValid {
		t.Errorf("Expected %v to be invalid but was %v", eOtp, isValid)
	}
}
