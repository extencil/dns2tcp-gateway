package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Mode represents the type of tunnel.
type Mode int

const (
	ModeUnknown Mode = iota
	ModeTCP
	ModeNS
	ModeRTCP
)

// String returns the human-readable name of the mode.
func (m Mode) String() string {
	switch m {
	case ModeTCP:
		return "tcp"
	case ModeNS:
		return "ns"
	case ModeRTCP:
		return "rtcp"
	default:
		return "unknown"
	}
}

// ParseMode converts a string to a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "tcp":
		return ModeTCP, nil
	case "ns":
		return ModeNS, nil
	case "rtcp":
		return ModeRTCP, nil
	default:
		return ModeUnknown, fmt.Errorf("session: unknown mode %q", s)
	}
}

// Session represents an active tunnel session.
type Session struct {
	ID        string    `json:"id"`
	Subdomain string    `json:"subdomain"`
	Mode      Mode      `json:"mode"`
	TargetIP  string    `json:"target_ip,omitempty"`
	TargetPort int      `json:"target_port,omitempty"`
	RTCPPort  int       `json:"rtcp_port,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	OwnerIP   string    `json:"owner_ip"`
	isActive  bool
}

// IsExpired returns true if the session has passed its expiry time.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsActive returns true if the session is active and not expired.
func (s *Session) IsActive() bool {
	return s.isActive && !s.IsExpired()
}

// Target returns the target as "ip:port" string.
func (s *Session) Target() string {
	if s.TargetIP == "" || s.TargetPort == 0 {
		return ""
	}
	return fmt.Sprintf("%s:%d", s.TargetIP, s.TargetPort)
}

// GenerateSubdomain creates a cryptographically random 6-character hex subdomain.
func GenerateSubdomain() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: generating subdomain: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateID creates a cryptographically random 16-character hex session ID.
func GenerateID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: generating id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
