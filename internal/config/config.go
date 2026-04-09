package config

import (
	"fmt"
	"net"
	"time"
)

// Config holds all configuration for the gateway.
type Config struct {
	// Domain is the base domain for tunnel subdomains (e.g. "thc.io").
	Domain string

	// DNSAddr is the listen address for the DNS server (e.g. ":53").
	DNSAddr string

	// APIAddr is the listen address for the REST API (e.g. ":8080").
	APIAddr string

	// Nameservers are the NS records returned for the zone (e.g. ["ns1.thc.io", "ns2.thc.io"]).
	Nameservers []string

	// GatewayIP is the public IP of this gateway server.
	GatewayIP string

	// SessionTTL is how long a tunnel session stays alive before auto-expiry.
	SessionTTL time.Duration

	// CleanupInterval is how often the session store runs expired session cleanup.
	CleanupInterval time.Duration

	// RTCPPortMin is the start of the RTCP port pool range.
	RTCPPortMin int

	// RTCPPortMax is the end of the RTCP port pool range.
	RTCPPortMax int

	// RateLimit is the max tunnel creation requests per IP per hour.
	RateLimit int

	// MaxTunnelsPerIP is the max concurrent tunnels allowed per source IP.
	MaxTunnelsPerIP int

	// DNSUDPSize is the EDNS0 UDP buffer size advertised by the DNS server.
	DNSUDPSize uint16

	// AdminContact is the RNAME field in the SOA record (email in DNS format).
	AdminContact string
}

// Default returns a Config populated with sensible production defaults.
func Default() Config {
	return Config{
		Domain:          "thc.io",
		DNSAddr:         ":53",
		APIAddr:         ":8080",
		Nameservers:     []string{"ns1.thc.io", "ns2.thc.io"},
		GatewayIP:       "127.0.0.1",
		SessionTTL:      1 * time.Hour,
		CleanupInterval: 5 * time.Minute,
		RTCPPortMin:     30000,
		RTCPPortMax:     40000,
		RateLimit:       30,
		MaxTunnelsPerIP: 5,
		DNSUDPSize:      4096,
		AdminContact:    "admin.thc.io",
	}
}

// Validate checks that all required fields are set and values are within acceptable ranges.
func (c Config) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("config: domain must not be empty")
	}
	if c.DNSAddr == "" {
		return fmt.Errorf("config: dns address must not be empty")
	}
	if c.APIAddr == "" {
		return fmt.Errorf("config: api address must not be empty")
	}
	if len(c.Nameservers) == 0 {
		return fmt.Errorf("config: at least one nameserver is required")
	}
	if net.ParseIP(c.GatewayIP) == nil {
		return fmt.Errorf("config: invalid gateway ip %q", c.GatewayIP)
	}
	if c.SessionTTL <= 0 {
		return fmt.Errorf("config: session ttl must be positive")
	}
	if c.RTCPPortMin >= c.RTCPPortMax {
		return fmt.Errorf("config: rtcp port min (%d) must be less than max (%d)", c.RTCPPortMin, c.RTCPPortMax)
	}
	if c.RateLimit <= 0 {
		return fmt.Errorf("config: rate limit must be positive")
	}
	if c.DNSUDPSize < 512 {
		return fmt.Errorf("config: dns udp size must be at least 512")
	}
	return nil
}

// FQDN returns the domain as a fully qualified domain name (trailing dot).
func (c Config) FQDN() string {
	d := c.Domain
	if d[len(d)-1] != '.' {
		d += "."
	}
	return d
}
