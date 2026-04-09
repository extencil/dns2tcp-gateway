package protocol

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// dns2tcp uses standard base64 without padding.
var encoding = base64.StdEncoding.WithPadding(base64.NoPadding)

// Command prefixes used in dns2tcp protocol.
// These appear as labels in the DNS query name: <data>.<command>.<domain>
const (
	CmdAuth     = "auth"
	CmdResource = "resource"
	CmdConnect  = "connect"
)

// ParsedQuery represents a decoded dns2tcp DNS query.
type ParsedQuery struct {
	Command string  // "auth", "resource", "connect", or "" for data queries
	Packet  *Packet // decoded protocol packet
	Raw     string  // raw query name for debugging
}

// DecodeQuery parses a dns2tcp DNS query name into its components.
// Query format: <base64-labels>=<command>.<domain> or <base64-labels>.<domain>
//
// The "=" prefix on the command label is how dns2tcp marks control messages.
// Data queries have no command prefix.
func DecodeQuery(qname, zone string) (*ParsedQuery, error) {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))

	if !strings.HasSuffix(qname, "."+zone) && qname != zone {
		return nil, fmt.Errorf("protocol: query %q not in zone %q", qname, zone)
	}

	// Strip the zone to get the prefix.
	prefix := strings.TrimSuffix(qname, "."+zone)
	if prefix == "" || prefix == zone {
		return nil, fmt.Errorf("protocol: empty prefix in query %q", qname)
	}

	result := &ParsedQuery{Raw: qname}

	// Split into labels and detect command.
	labels := strings.Split(prefix, ".")
	if len(labels) == 0 {
		return nil, fmt.Errorf("protocol: no labels in query prefix %q", prefix)
	}

	// Check for command label (prefixed with "=" in dns2tcp).
	// The command is the last label before the zone.
	lastLabel := labels[len(labels)-1]
	if strings.HasPrefix(lastLabel, "=") {
		result.Command = strings.TrimPrefix(lastLabel, "=")
		labels = labels[:len(labels)-1] // remove command label from data
	}

	// Reassemble base64 data: strip dots between labels, they're just DNS label separators.
	encoded := strings.Join(labels, "")

	if encoded == "" {
		// Command-only query with no data payload.
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
// This is what goes into a DNS TXT or KEY record answer.
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
