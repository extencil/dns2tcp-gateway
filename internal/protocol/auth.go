package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

const challengeLen = 16

// GenerateChallenge creates a 16-character alphanumeric challenge string,
// matching dns2tcp's alphanum_random() charset (A-Z0-9).
func GenerateChallenge() (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, challengeLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("protocol: generating challenge: %w", err)
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b), nil
}

// ComputeHMAC returns the uppercase hex HMAC-SHA1 of the challenge using the key,
// matching dns2tcp's CHAP authentication.
func ComputeHMAC(key, challenge string) string {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(challenge))
	return strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
}

// VerifyHMAC checks if the client's HMAC response matches the expected value.
func VerifyHMAC(key, challenge, clientResponse string) bool {
	expected := ComputeHMAC(key, challenge)
	return hmac.Equal([]byte(expected), []byte(strings.ToUpper(clientResponse)))
}
