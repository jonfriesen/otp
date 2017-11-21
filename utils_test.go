package otp

import (
	"testing"
)

func TestSecret(t *testing.T) {
	s := Secret()

	if len(s) != 20 {
		t.Errorf("Secret %v was not the expected length of 20", s)
	}
}
