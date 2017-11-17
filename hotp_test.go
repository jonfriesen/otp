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

func TestGenerate(t *testing.T) {
	secret := []byte("12345678901234567890")
	testValues := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	length := 6

	for i, v := range testValues {
		otp := Generate(secret, uint64(i), length)
		if otp != v {
			t.Errorf("Expected %v to be %v", otp, v)
		}
	}
}

func TestCheck(t *testing.T) {
	secret := []byte("12345678901234567890")
	length := 6

	v, i := Check(secret, 0, length, "755224", 1)
	if !v || i != 0 {
		t.Error("HOTP at spot 1 did not succeed")
	}

	v, i = Check(secret, 1, length, "969429", 3)
	if !v || i != 3 {
		t.Error("HOTP did not count into the future as expected")
	}

	v, i = Check(secret, 2, length, "520489", 3)
	if v {
		t.Error("HOTP Check succeeded when expected to fail")
	}
}

func TestSync(t *testing.T) {
	secret := []byte("12345678901234567890")
	length := 6

	v, i := Sync(secret, 0, length, "755224", "287082")
	if !v || i != 1 {
		t.Error("HOTP Sync at beginning failed")
	}

	v, i = Sync(secret, 0, length, "254676", "287922")
	if !v || i != 6 {
		t.Error("HOTP future sync failed")
	}

	v, i = Sync(secret, 0, length, "123456", "520489")
	if v {
		t.Error("HOTP expected to not find first OTP")
	}

	v, i = Sync(secret, 0, length, "254676", "520489")
	if v {
		t.Error("HOTP expected to not find second OTP")
	}
}
