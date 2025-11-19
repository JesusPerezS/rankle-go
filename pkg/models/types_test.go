package models

import (
	"testing"
	"time"
)

func TestScanResult(t *testing.T) {
	result := &ScanResult{
		Domain:    "example.com",
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	if result.Domain != "example.com" {
		t.Errorf("Domain = %s; want example.com", result.Domain)
	}

	if result.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
}

func TestHTTPAnalysis(t *testing.T) {
	analysis := &HTTPAnalysis{
		StatusCode:   200,
		Server:       "nginx",
		Headers:      make(map[string]string),
		ResponseTime: 100,
	}

	if analysis.StatusCode != 200 {
		t.Errorf("StatusCode = %d; want 200", analysis.StatusCode)
	}

	if analysis.Server != "nginx" {
		t.Errorf("Server = %s; want nginx", analysis.Server)
	}
}

func TestDNSAnalysis(t *testing.T) {
	dns := &DNSAnalysis{
		A:     []string{"93.184.216.34"},
		AAAA:  []string{"2606:2800:220:1:248:1893:25c8:1946"},
		CNAME: []string{},
	}

	if len(dns.A) != 1 {
		t.Errorf("A records count = %d; want 1", len(dns.A))
	}

	if dns.A[0] != "93.184.216.34" {
		t.Errorf("A[0] = %s; want 93.184.216.34", dns.A[0])
	}
}

func TestTechnologies(t *testing.T) {
	tech := &Technologies{
		CMS:        "WordPress",
		Frameworks: []string{"Next.js"},
		Libraries:  []string{"jQuery", "Bootstrap"},
	}

	if tech.CMS != "WordPress" {
		t.Errorf("CMS = %s; want WordPress", tech.CMS)
	}

	if len(tech.Libraries) != 2 {
		t.Errorf("Libraries count = %d; want 2", len(tech.Libraries))
	}
}

func TestGeolocation(t *testing.T) {
	geo := &Geolocation{
		IP:          "93.184.216.34",
		Country:     "United States",
		CountryCode: "US",
		City:        "New York",
		ISP:         "Example ISP",
	}

	if geo.IP != "93.184.216.34" {
		t.Errorf("IP = %s; want 93.184.216.34", geo.IP)
	}

	if geo.Country != "United States" {
		t.Errorf("Country = %s; want United States", geo.Country)
	}
}
