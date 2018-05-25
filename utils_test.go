package otp

import (
	"testing"
)

func TestSecret_noEncoding(t *testing.T) {
	t.Parallel()

	s := Secret(false)
	if len(s) != 20 {
		t.Errorf("Secret %v was not the expected length of 20", s)
	}
}

func TestSecret_base32(t *testing.T) {
	t.Parallel()

	s32 := Secret(true)
	if len(s32) != 32 {
		t.Errorf("Secret (base32) %v was not the expected length of 20", s32)
	}
}
