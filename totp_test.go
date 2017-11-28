package otp

import (
	"testing"
	"time"
)

const (
	secret256 string = "12345678901234567890123456789012"
	secret512 string = "1234567890123456789012345678901234567890123456789012345678901234"
)

type hashConfig struct {
	secret string
	otp    string
	crypto string
}

func getTimeTestMap() map[time.Time][]hashConfig {
	return map[time.Time][]hashConfig{
		time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC): []hashConfig{
			hashConfig{defaultSecret, `94287082`, "sha1"},
			hashConfig{secret256, `46119246`, "sha256"},
			hashConfig{secret512, `90693936`, "sha512"},
		},
		time.Date(2005, 3, 18, 1, 58, 29, 0, time.UTC): []hashConfig{
			hashConfig{defaultSecret, `07081804`, "sha1"},
			hashConfig{secret256, `68084774`, "sha256"},
			hashConfig{secret512, `25091201`, "sha512"},
		},
		time.Date(2005, 3, 18, 1, 58, 31, 0, time.UTC): []hashConfig{
			hashConfig{defaultSecret, `14050471`, "sha1"},
			hashConfig{secret256, `67062674`, "sha256"},
			hashConfig{secret512, `99943326`, "sha512"},
		},
		time.Date(2009, 2, 13, 23, 31, 30, 0, time.UTC): []hashConfig{
			hashConfig{defaultSecret, `89005924`, "sha1"},
			hashConfig{secret256, `91819424`, "sha256"},
			hashConfig{secret512, `93441116`, "sha512"},
		},
		time.Date(2033, 5, 18, 3, 33, 20, 0, time.UTC): []hashConfig{
			hashConfig{defaultSecret, `69279037`, "sha1"},
			hashConfig{secret256, `90698825`, "sha256"},
			hashConfig{secret512, `38618901`, "sha512"},
		},
		time.Date(2603, 10, 11, 11, 33, 20, 0, time.UTC): []hashConfig{
			hashConfig{defaultSecret, `65353130`, "sha1"},
			hashConfig{secret256, `77737706`, "sha256"},
			hashConfig{secret512, `47863826`, "sha512"},
		},
	}
}

func TestGenerateTotp(t *testing.T) {
	timeMap := getTimeTestMap()

	for tm, otpHashMap := range timeMap {
		for _, hc := range otpHashMap {
			c := TotpConfig{secret: hc.secret, time: tm, crypto: hc.crypto}
			otp := NewTOTP(&c)
			rOtp := otp.Generate()

			if rOtp != hc.otp {
				t.Errorf("Expected %v but got %v", hc.otp, rOtp)
			}
		}
	}
}

func TestCheckTotp(t *testing.T) {
	timeMap := getTimeTestMap()
	for tm, otpHashMap := range timeMap {
		for _, hc := range otpHashMap {

			c := TotpConfig{secret: hc.secret, time: tm, crypto: hc.crypto}
			otp := NewTOTP(&c)
			isValid := otp.Check(hc.otp)
			if !isValid {
				t.Errorf("Expected %v to be valid but was %v", hc.otp, isValid)
			}

			// Base32 tests
			otp32 := NewTOTP(&c)
			isValid32 := otp32.Check(hc.otp)
			if !isValid32 {
				t.Errorf("Expected base32 encoded %v to be valid but was %v", hc.otp, isValid32)
			}
		}
	}

	c := TotpConfig{
		secret: defaultSecret,
		time:   time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC),
	}
	otp := NewTOTP(&c)
	isValid := otp.Check("12345678")
	if isValid {
		t.Errorf("Expected %v to be invalid but was 94287082", isValid)
	}
}

func TestNewTOTP(t *testing.T) {
	testTime := time.Date(1970, 1, 1, 0, 0, 59, 0, time.UTC)
	cConfig := TotpConfig{
		secret:     "secret",
		time:       testTime,
		length:     10,
		window:     45,
		windowSize: 3,
	}
	cToken := NewTOTP(&cConfig)

	if cToken.secret != "secret" ||
		cToken.timeBox != testTime ||
		cToken.length != 10 ||
		cToken.window != 45 ||
		cToken.windowSize != 3 {
		t.Errorf("NewTOTP (custom) returned an object with unexpected properties %+v", cToken)
	}

	testTime = time.Now()
	dConfig := TotpConfig{}
	dToken := NewTOTP(&dConfig)

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
