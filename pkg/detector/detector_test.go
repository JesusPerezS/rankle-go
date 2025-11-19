package detector

import (
	"testing"
)

func TestNew(t *testing.T) {
	detector := New()
	if detector == nil {
		t.Fatal("Detector should not be nil")
	}
}

func TestDetectCMS(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "WordPress detection",
			body:     "<html><body>This site uses wp-content and wp-includes</body></html>",
			headers:  map[string]string{},
			expected: "WordPress",
		},
		{
			name:     "Drupal detection",
			body:     "<html><body>drupal.js and drupal-settings-json</body></html>",
			headers:  map[string]string{"x-generator": "Drupal 9"},
			expected: "Drupal",
		},
		{
			name:     "Joomla detection",
			body:     "<html><body>/components/com_content and option=com_content</body></html>",
			headers:  map[string]string{},
			expected: "Joomla",
		},
		{
			name:     "No CMS",
			body:     "<html><body>Just a plain website</body></html>",
			headers:  map[string]string{},
			expected: "",
		},
	}

	detector := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.detectCMS(tt.body, tt.headers)
			if result != tt.expected {
				t.Errorf("detectCMS() = %s; want %s", result, tt.expected)
			}
		})
	}
}

func TestDetectLibraries(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected []string
	}{
		{
			name:     "jQuery detection",
			body:     "<script src='/js/jquery.min.js'></script>",
			expected: []string{"jQuery"},
		},
		{
			name:     "Multiple libraries",
			body:     "<script src='jquery.js'></script><link href='bootstrap.min.css'></link>",
			expected: []string{"jQuery", "Bootstrap"},
		},
		{
			name:     "No libraries",
			body:     "<html><body>No libraries here</body></html>",
			expected: []string{},
		},
	}

	detector := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.detectLibraries(tt.body)
			if len(result) != len(tt.expected) {
				t.Errorf("detectLibraries() returned %d libraries; want %d", len(result), len(tt.expected))
			}
		})
	}
}

func TestDetectCDN(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		cnames   []string
		expected string
	}{
		{
			name:     "Cloudflare detection from header",
			headers:  map[string]string{"cf-ray": "12345"},
			cnames:   []string{},
			expected: "Cloudflare",
		},
		{
			name:     "Akamai detection from CNAME",
			headers:  map[string]string{},
			cnames:   []string{"example.akamaihd.net"},
			expected: "Akamai",
		},
		{
			name:     "No CDN",
			headers:  map[string]string{},
			cnames:   []string{},
			expected: "",
		},
	}

	detector := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.DetectCDN(tt.headers, tt.cnames)
			if result != tt.expected {
				t.Errorf("DetectCDN() = %s; want %s", result, tt.expected)
			}
		})
	}
}

func TestDetectWAF(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "Cloudflare WAF",
			headers:  map[string]string{"cf-ray": "12345"},
			expected: "Cloudflare WAF",
		},
		{
			name:     "Imperva WAF",
			headers:  map[string]string{"x-iinfo": "some-value"},
			expected: "Imperva WAF",
		},
		{
			name:     "No WAF",
			headers:  map[string]string{"server": "nginx"},
			expected: "",
		},
	}

	detector := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.DetectWAF(tt.headers, nil)
			if result != tt.expected {
				t.Errorf("DetectWAF() = %s; want %s", result, tt.expected)
			}
		})
	}
}

func TestDetectCloudProvider(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		hostname string
		isp      string
		expected string
	}{
		{
			name:     "AWS detection",
			ip:       "52.1.1.1",
			hostname: "ec2-52-1-1-1.compute.amazonaws.com",
			isp:      "Amazon",
			expected: "Amazon AWS",
		},
		{
			name:     "Google Cloud detection",
			ip:       "35.1.1.1",
			hostname: "1.1.1.35.bc.googleusercontent.com",
			isp:      "Google",
			expected: "Google Cloud",
		},
		{
			name:     "No cloud provider",
			ip:       "1.2.3.4",
			hostname: "example.com",
			isp:      "Local ISP",
			expected: "",
		},
	}

	detector := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.DetectCloudProvider(tt.ip, tt.hostname, tt.isp)
			if result != tt.expected {
				t.Errorf("DetectCloudProvider() = %s; want %s", result, tt.expected)
			}
		})
	}
}
