package hotp

import (
	"reflect"
	"testing"
)

func TestHmacSha1(t *testing.T) {

	key := []byte("test-key")
	input := []byte("test-input")

	bs := hmacSha1(key, input)

	expected := []byte{129, 193, 195, 181, 158, 69, 154, 83, 195, 51, 192, 169, 95, 175, 198, 185, 45, 64, 69, 169}

	if reflect.DeepEqual(bs, expected) == false {
		t.Errorf("HMAC SHA1 is wrong: %+v", bs)
	}
}

func TestGenerateOtp(t *testing.T) {
	secret := []byte("12345678901234567890")
	testValues := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	length := 6

	for i, v := range testValues {
		otp := GenerateOTP(secret, uint64(i), length)
		if otp != v {
			t.Errorf("Expected %v to be %v", otp, v)
		}
	}
}
