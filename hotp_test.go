package otp

import (
	"reflect"
	"testing"
)

const (
	defaultSecret string = "12345678901234567890"
	defaultLength int    = 6
)

func TestHmacSha1(t *testing.T) {
	input := []byte("test-input")

	bs := hmacSha1(defaultSecret, input)

	expected := []byte{206, 196, 29, 189, 198, 222, 88, 115, 62, 215, 116, 67, 206, 130, 89, 12, 146, 242, 197, 164}

	if reflect.DeepEqual(bs, expected) == false {
		t.Errorf("HMAC SHA1 is wrong: %+v", bs)
	}
}

func TestGenerate(t *testing.T) {
	testValues := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}

	for i, v := range testValues {
		h := NewHOTP(defaultSecret, i, 0, 0)
		h.count = i
		otp := h.Generate()
		if otp != v {
			t.Errorf("Expected %v to be %v", otp, v)
		}
	}
}

func TestCheck(t *testing.T) {

	h := NewHOTP(defaultSecret, 0, 0, 1)
	v, i := h.Check("755224")
	if !v || i != 0 {
		t.Error("HOTP at spot 1 did not succeed")
	}

	h = NewHOTP(defaultSecret, 1, 0, 3)
	v, i = h.Check("969429")
	if !v || i != 3 {
		t.Error("HOTP did not count into the future as expected")
	}

	h = NewHOTP(defaultSecret, 2, 0, 3)
	v, i = h.Check("520489")
	if v {
		t.Error("HOTP Check succeeded when expected to fail")
	}
}

func TestSync(t *testing.T) {

	h := NewHOTP(defaultSecret, 0, 0, 0)
	v, i := h.Sync("755224", "287082")
	if !v || i != 2 {
		t.Error("HOTP Sync at beginning failed")
	}

	v, i = h.Sync("254676", "287922")
	if !v || i != 7 {
		t.Error("HOTP future sync failed")
	}

	v, i = h.Sync("123456", "520489")
	if v {
		t.Error("HOTP expected to not find first OTP")
	}

	v, i = h.Sync("254676", "520489")
	if v {
		t.Error("HOTP expected to not find second OTP")
	}
}
