package models

import "time"

// ScanResult contains all the results from a domain scan
type ScanResult struct {
	Domain          string                 `json:"domain"`
	Timestamp       time.Time              `json:"timestamp"`
	HTTP            *HTTPAnalysis          `json:"http,omitempty"`
	DNS             *DNSAnalysis           `json:"dns,omitempty"`
	TLS             *TLSAnalysis           `json:"tls,omitempty"`
	Technologies    *Technologies          `json:"technologies,omitempty"`
	CDN             string                 `json:"cdn,omitempty"`
	WAF             string                 `json:"waf,omitempty"`
	CloudProvider   string                 `json:"cloud_provider,omitempty"`
	Geolocation     *Geolocation           `json:"geolocation,omitempty"`
	Subdomains      []string               `json:"subdomains,omitempty"`
	SecurityHeaders map[string]string      `json:"security_headers,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// HTTPAnalysis contains HTTP-related information
type HTTPAnalysis struct {
	StatusCode   int               `json:"status_code"`
	Server       string            `json:"server,omitempty"`
	Headers      map[string]string `json:"headers"`
	ResponseTime int64             `json:"response_time_ms"`
	RedirectURL  string            `json:"redirect_url,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
}

// DNSAnalysis contains DNS records
type DNSAnalysis struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME []string `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	SOA   string   `json:"soa,omitempty"`
}

// TLSAnalysis contains TLS/SSL certificate information
type TLSAnalysis struct {
	Version      string    `json:"version"`
	CipherSuite  string    `json:"cipher_suite"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SANs         []string  `json:"sans,omitempty"`
	SignatureAlg string    `json:"signature_algorithm"`
	PublicKeyAlg string    `json:"public_key_algorithm"`
}

// Technologies contains detected web technologies
type Technologies struct {
	CMS         string   `json:"cms,omitempty"`
	Frameworks  []string `json:"frameworks,omitempty"`
	Libraries   []string `json:"libraries,omitempty"`
	Languages   []string `json:"languages,omitempty"`
	Analytics   []string `json:"analytics,omitempty"`
	WebServers  []string `json:"web_servers,omitempty"`
	Fingerprint []string `json:"fingerprint,omitempty"`
}

// Geolocation contains location and ISP information
type Geolocation struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	ASN         string  `json:"asn,omitempty"`
	Hostname    string  `json:"hostname,omitempty"`
}
