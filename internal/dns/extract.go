package dns

import (
	"strings"

	"github.com/miekg/dns"
)

// extractSubdomain extracts the first-level subdomain from a query name
// relative to the zone. For example, given "data.abc123.thc.io." and zone
// "thc.io.", it returns "abc123".
//
// If the query is for the zone apex itself, it returns "".
// If there are multiple labels before the zone, the second-to-last label
// (the direct child of the zone) is treated as the session subdomain.
func extractSubdomain(qname, zone string) string {
	qname = dns.CanonicalName(qname)
	zone = dns.CanonicalName(zone)

	if !strings.HasSuffix(qname, zone) {
		return ""
	}

	// Strip the zone suffix to get the prefix labels.
	prefix := strings.TrimSuffix(qname, zone)
	prefix = strings.TrimSuffix(prefix, ".")

	if prefix == "" {
		return ""
	}

	// Split into labels. The last label in the prefix is the session subdomain.
	// Example: "data.abc123" -> labels ["data", "abc123"] -> subdomain is "abc123"
	labels := strings.Split(prefix, ".")
	return labels[len(labels)-1]
}
