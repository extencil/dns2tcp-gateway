package protocol

import (
	"testing"
)

func TestGenerateChallenge(t *testing.T) {
	c, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	if len(c) != 16 {
		t.Errorf("challenge length = %d, want 16", len(c))
	}

	// Should only contain A-Z0-9.
	for _, ch := range c {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
			t.Errorf("invalid char %c in challenge", ch)
		}
	}
}

func TestHMACVerify(t *testing.T) {
	key := "testkey"
	challenge := "ABCDEF1234567890"

	hmacResult := ComputeHMAC(key, challenge)

	if !VerifyHMAC(key, challenge, hmacResult) {
		t.Error("HMAC verification failed for correct key")
	}

	if VerifyHMAC("wrongkey", challenge, hmacResult) {
		t.Error("HMAC verification should fail for wrong key")
	}
}

func TestHMACCaseInsensitive(t *testing.T) {
	key := "mykey"
	challenge := "TEST1234ABCD5678"

	upper := ComputeHMAC(key, challenge)

	// Client might send lowercase.
	if !VerifyHMAC(key, challenge, upper) {
		t.Error("HMAC should accept uppercase")
	}
}
