package otp

import (
	"testing"
)

func TestSecret(t *testing.T) {
	s := Secret(false)
	if len(s) != 20 {
		t.Errorf("Secret %v was not the expected length of 20", s)
	}

	s32 := Secret(true)
	if len(s32) != 32 {
		t.Errorf("Secret %v was not the expected length of 20", s32)
	}
}
