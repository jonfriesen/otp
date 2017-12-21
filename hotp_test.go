package otp

import (
	"crypto/sha1"
	"reflect"
	"testing"
)

const (
	defaultSecret string = "12345678901234567890"
	defaultLength int    = 6
)

func TestHmacSha(t *testing.T) {
	input := []byte("test-input")

	bs := hmacSha(defaultSecret, input, sha1.New)

	expected := []byte{206, 196, 29, 189, 198, 222, 88, 115, 62, 215, 116, 67, 206, 130, 89, 12, 146, 242, 197, 164}

	if reflect.DeepEqual(bs, expected) == false {
		t.Errorf("HMAC SHA1 is wrong: %+v", bs)
	}
}

func TestGenerate(t *testing.T) {
	testValues := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}

	for i, v := range testValues {
		c := HotpConfig{Secret: defaultSecret, Count: i}
		h := NewHOTP(&c)
		// h := NewHOTP(defaultSecret, i, 0, 0, false, nil)
		h.Count = i
		otp := h.Generate()
		if otp != v {
			t.Errorf("Expected %v to be %v", otp, v)
		}

		// Base32 tests
		h32 := NewHOTP(&c)
		h32.Count = i
		otp32 := h32.Generate()
		if otp32 != v {
			t.Errorf("Expected base32 encoded %v to be %v", otp32, v)
		}
	}
}

func TestCheck(t *testing.T) {
	c := HotpConfig{Secret: defaultSecret, Window: 1}
	h := NewHOTP(&c)
	v, i := h.Check("755224")
	if !v || i != 0 {
		t.Error("HOTP at spot 1 did not succeed")
	}

	c = HotpConfig{Secret: defaultSecret, Count: 1, Window: 3}
	h = NewHOTP(&c)
	v, i = h.Check("969429")
	if !v || i != 3 {
		t.Error("HOTP did not count into the future as expected")
	}

	c = HotpConfig{Secret: defaultSecret, Count: 2, Window: 3}
	h = NewHOTP(&c)
	v, i = h.Check("520489")
	if v {
		t.Error("HOTP Check succeeded when expected to fail")
	}
}

func TestSync(t *testing.T) {

	c := HotpConfig{Secret: defaultSecret}
	h := NewHOTP(&c)
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

func TestNewHotp(t *testing.T) {
	dConfig := HotpConfig{}
	dToken := NewHOTP(&dConfig)
	if len(dToken.Secret) != 20 ||
		dToken.Count != 0 ||
		dToken.Length != 6 ||
		dToken.Window != 5 ||
		dToken.IsBase32 != false {
		t.Errorf("NewHOTP (default) returned an object with unexpected properties %+v", dToken)
	}

	cConfig := HotpConfig{"secret", 5, 3, 100, true, "sha1"}
	cToken := NewHOTP(&cConfig)
	if cToken.Secret != "secret" ||
		cToken.Count != 5 ||
		cToken.Length != 3 ||
		cToken.Window != 100 ||
		cToken.IsBase32 != true {
		t.Errorf("NewHOTP (custom) returned an object with unexpected properties %+v", cToken)
	}
}
