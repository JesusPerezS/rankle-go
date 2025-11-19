package scanner

import (
	"testing"

	"github.com/javicosvml/rankle-go/internal/config"
)

func TestNew(t *testing.T) {
	cfg := config.Default()
	scanner := New(cfg)

	if scanner == nil {
		t.Fatal("Scanner should not be nil")
	}

	if scanner.config == nil {
		t.Fatal("Scanner config should not be nil")
	}

	if scanner.client == nil {
		t.Fatal("Scanner HTTP client should not be nil")
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple domain",
			input:    "example.com",
			expected: "example.com",
		},
		{
			name:     "Domain with http",
			input:    "http://example.com",
			expected: "example.com",
		},
		{
			name:     "Domain with https",
			input:    "https://example.com",
			expected: "example.com",
		},
		{
			name:     "Domain with port",
			input:    "example.com:8080",
			expected: "example.com",
		},
		{
			name:     "Domain with path",
			input:    "example.com/path",
			expected: "example.com",
		},
		{
			name:     "Full URL",
			input:    "https://example.com:443/path",
			expected: "example.com",
		},
	}

	scanner := New(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.normalizeDomain(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeDomain(%s) = %s; want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEnsureHTTPS(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple domain",
			input:    "example.com",
			expected: "https://example.com",
		},
		{
			name:     "Domain with http",
			input:    "http://example.com",
			expected: "https://example.com",
		},
		{
			name:     "Domain with https",
			input:    "https://example.com",
			expected: "https://example.com",
		},
	}

	scanner := New(nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.ensureHTTPS(tt.input)
			if result != tt.expected {
				t.Errorf("ensureHTTPS(%s) = %s; want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestScan(t *testing.T) {
	scanner := New(nil)
	result, err := scanner.Scan("example.com")

	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result.Domain != "example.com" {
		t.Errorf("Domain = %s; want example.com", result.Domain)
	}

	if result.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
}
