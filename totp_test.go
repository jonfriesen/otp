package otp

import (
	"testing"
	"time"
)

func TestGenerateTotp(t *testing.T) {
	tm := time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC)

	otp := NewTOTP(defaultSecret, tm, 0, 0, 0)

	eOtp := "94287082"
	rOtp := otp.Generate()

	if rOtp != eOtp {
		t.Errorf("Expected %v but got %v", eOtp, rOtp)
	}
}

func TestCheckTotp(t *testing.T) {
	tm := time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC)

	otp := NewTOTP(defaultSecret, tm, 0, 0, 0)
	eOtp := "94287082"
	isValid := otp.Check(eOtp)
	if !isValid {
		t.Errorf("Expected %v to be valid but was %v", eOtp, isValid)
	}

	isValid = otp.Check("12345678")
	if isValid {
		t.Errorf("Expected %v to be invalid but was %v", eOtp, isValid)
	}
}
