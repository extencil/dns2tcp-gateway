package protocol

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// dns2tcp uses standard base64 without padding.
var encoding = base64.StdEncoding.WithPadding(base64.NoPadding)

// Command prefixes used in dns2tcp protocol.
// These appear as labels in the DNS query name: <data>.=<command>.<subdomain>.<zone>
const (
	CmdAuth     = "auth"
	CmdResource = "resource"
	CmdConnect  = "connect"
)

// ParsedQuery represents a decoded dns2tcp DNS query.
type ParsedQuery struct {
	Command   string  // "auth", "resource", "connect", or "" for data queries
	Subdomain string  // the session subdomain (e.g. "m6kfjz")
	Packet    *Packet // decoded protocol packet
	Raw       string  // raw query name for debugging
}

// DecodeQuery parses a dns2tcp DNS query name into its components.
//
// dns2tcpc is configured with domain = "<subdomain>.<zone>" (e.g. "m6kfjz.tun.numex.sh").
// It sends queries in the format:
//
//	<base64-data>.=<command>.<subdomain>.<zone>
//
// For data queries (no command):
//
//	<base64-data>.<subdomain>.<zone>
//
// This function strips the zone, identifies the subdomain (last label),
// finds the command (label with "=" prefix), and decodes the base64 data.
func DecodeQuery(qname, zone string) (*ParsedQuery, error) {
	// Trim trailing dot but preserve original case for base64 data.
	qname = strings.TrimSuffix(qname, ".")
	zone = strings.TrimSuffix(zone, ".")

	// Case-insensitive zone matching (DNS is case-insensitive for domain names).
	qnameLower := strings.ToLower(qname)
	zoneLower := strings.ToLower(zone)

	if !strings.HasSuffix(qnameLower, "."+zoneLower) && qnameLower != zoneLower {
		return nil, fmt.Errorf("protocol: query %q not in zone %q", qname, zone)
	}

	// Strip the zone from the ORIGINAL case query to preserve base64 data.
	// Zone length is the same regardless of case.
	prefix := qname[:len(qname)-len(zone)-1]
	if prefix == "" {
		return nil, fmt.Errorf("protocol: empty prefix in query %q", qname)
	}

	result := &ParsedQuery{Raw: qname}

	// Split into labels.
	labels := strings.Split(prefix, ".")
	if len(labels) == 0 {
		return nil, fmt.Errorf("protocol: no labels in query prefix %q", prefix)
	}

	// The last label is the session subdomain (case-insensitive, lowercase it).
	result.Subdomain = strings.ToLower(labels[len(labels)-1])
	labels = labels[:len(labels)-1]

	// If only the subdomain was present (direct subdomain query, no data).
	if len(labels) == 0 {
		return result, nil
	}

	// Scan remaining labels for the command (prefixed with "=").
	// Command is case-insensitive, data labels preserve original case for base64.
	var dataLabels []string
	for _, label := range labels {
		if strings.HasPrefix(label, "=") || strings.HasPrefix(label, "=") {
			result.Command = strings.ToLower(strings.TrimPrefix(label, "="))
		} else {
			dataLabels = append(dataLabels, label)
		}
	}

	// Reassemble base64 data: join labels (dots are just DNS label separators).
	encoded := strings.Join(dataLabels, "")

	if encoded == "" {
		return result, nil
	}

	// Base64 decode.
	raw, err := encoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("protocol: base64 decode: %w", err)
	}

	// Parse the packet.
	pkt, err := Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("protocol: unmarshal packet: %w", err)
	}

	result.Packet = pkt
	return result, nil
}

// EncodeResponse builds a base64-encoded response payload from a packet.
func EncodeResponse(p *Packet) string {
	return encoding.EncodeToString(p.Marshal())
}

// EncodeTXTResponse builds a TXT record value.
// dns2tcp TXT responses prepend a single-char index ('A' + answerIndex)
// followed by the base64-encoded packet data.
func EncodeTXTResponse(p *Packet, answerIndex int) string {
	indexChar := byte('A') + byte(answerIndex)
	encoded := encoding.EncodeToString(p.Marshal())
	return string(indexChar) + encoded
}
