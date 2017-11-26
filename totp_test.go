package otp

import (
	"testing"
	"time"
)

func TestGenerateTotp(t *testing.T) {
	timeMap := map[time.Time]string{
		time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC):     `94287082`,
		time.Date(2005, 3, 18, 1, 58, 29, 0, time.UTC):   `07081804`,
		time.Date(2005, 3, 18, 1, 58, 31, 0, time.UTC):   `14050471`,
		time.Date(2009, 2, 13, 23, 31, 30, 0, time.UTC):  `89005924`,
		time.Date(2033, 5, 18, 3, 33, 20, 0, time.UTC):   `69279037`,
		time.Date(2603, 10, 11, 11, 33, 20, 0, time.UTC): `65353130`,
	}

	for tm, eOtp := range timeMap {
		otp := NewTOTP(defaultSecret, tm, 0, 0, 0, false, nil)
		rOtp := otp.Generate()

		if rOtp != eOtp {
			t.Errorf("Expected %v but got %v", eOtp, rOtp)
		}
	}
}

func TestCheckTotp(t *testing.T) {
	timeMap := map[time.Time]string{
		time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC):     `94287082`,
		time.Date(2005, 3, 18, 1, 58, 29, 0, time.UTC):   `07081804`,
		time.Date(2005, 3, 18, 1, 58, 31, 0, time.UTC):   `14050471`,
		time.Date(2009, 2, 13, 23, 31, 30, 0, time.UTC):  `89005924`,
		time.Date(2033, 5, 18, 3, 33, 20, 0, time.UTC):   `69279037`,
		time.Date(2603, 10, 11, 11, 33, 20, 0, time.UTC): `65353130`,
	}

	for tm, eOtp := range timeMap {
		otp := NewTOTP(defaultSecret, tm, 0, 0, 0, false, nil)
		isValid := otp.Check(eOtp)
		if !isValid {
			t.Errorf("Expected %v to be valid but was %v", eOtp, isValid)
		}

		// Base32 tests
		otp32 := NewTOTP(defaultSecret, tm, 0, 0, 0, true, nil)
		isValid32 := otp32.Check(eOtp)
		if !isValid32 {
			t.Errorf("Expected base32 encoded %v to be valid but was %v", eOtp, isValid32)
		}
	}

	testTime := time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC)
	otp := NewTOTP(defaultSecret, testTime, 0, 0, 0, false, nil)
	isValid := otp.Check("12345678")
	if isValid {
		t.Errorf("Expected %v to be invalid but was 94287082", isValid)
	}
}

func TestNewTOTP(t *testing.T) {
	testTime := time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC)
	cToken := NewTOTP("secret", testTime, 10, 45, 3, false, nil)

	if cToken.secret != "secret" ||
		cToken.timeBox != testTime ||
		cToken.length != 10 ||
		cToken.window != 45 ||
		cToken.windowSize != 3 {
		t.Errorf("NewTOTP (custom) returned an object with unexpected properties %+v", cToken)
	}

	testTime = time.Now()
	dToken := NewTOTP("", time.Time{}, 0, 0, 0, false, nil)

	isTimeSimilar :=
		testTime.Minute() == dToken.timeBox.Minute() &&
			testTime.Hour() == dToken.timeBox.Hour() &&
			testTime.Day() == dToken.timeBox.Day() &&
			testTime.Month() == dToken.timeBox.Month() &&
			testTime.Year() == dToken.timeBox.Year()

	if len(dToken.secret) != 20 ||
		!isTimeSimilar ||
		dToken.length != 8 ||
		dToken.window != 30 ||
		dToken.windowSize != 2 {
		t.Errorf("NewTOTP (default) returned an object with unexpected properties %+v", dToken)
	}
}
