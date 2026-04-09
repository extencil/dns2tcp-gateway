package dns

import "testing"

func TestExtractSubdomain(t *testing.T) {
	tests := []struct {
		name     string
		qname    string
		zone     string
		expected string
	}{
		{
			name:     "zone apex",
			qname:    "thc.io.",
			zone:     "thc.io.",
			expected: "",
		},
		{
			name:     "direct subdomain",
			qname:    "abc123.thc.io.",
			zone:     "thc.io.",
			expected: "abc123",
		},
		{
			name:     "nested labels, subdomain is second level",
			qname:    "data.seq001.abc123.thc.io.",
			zone:     "thc.io.",
			expected: "abc123",
		},
		{
			name:     "single data label above subdomain",
			qname:    "aGVsbG8.abc123.thc.io.",
			zone:     "thc.io.",
			expected: "abc123",
		},
		{
			name:     "different zone",
			qname:    "test.example.com.",
			zone:     "thc.io.",
			expected: "",
		},
		{
			name:     "case insensitive",
			qname:    "ABC123.THC.IO.",
			zone:     "thc.io.",
			expected: "abc123",
		},
		{
			name:     "no trailing dot on input",
			qname:    "abc123.thc.io",
			zone:     "thc.io",
			expected: "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSubdomain(tt.qname, tt.zone)
			if got != tt.expected {
				t.Errorf("extractSubdomain(%q, %q) = %q, want %q", tt.qname, tt.zone, got, tt.expected)
			}
		})
	}
}
