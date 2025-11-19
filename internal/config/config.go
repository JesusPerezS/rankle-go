package config

import "time"

// Config holds application configuration
type Config struct {
	HTTP    HTTPConfig
	DNS     DNSConfig
	TLS     TLSConfig
	Scanner ScannerConfig
}

// HTTPConfig contains HTTP client configuration
type HTTPConfig struct {
	Timeout        time.Duration
	ShortTimeout   time.Duration
	MaxRetries     int
	RetryDelay     time.Duration
	UserAgent      string
	FollowRedirect bool
}

// DNSConfig contains DNS resolver configuration
type DNSConfig struct {
	Timeout     time.Duration
	Nameservers []string
}

// TLSConfig contains TLS connection configuration
type TLSConfig struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

// ScannerConfig contains scanner-specific settings
type ScannerConfig struct {
	MinCMSIndicators       int
	MinCMSIndicatorsNoMeta int
	MaxSubdomainsDisplay   int
}

// Default returns a configuration with sensible defaults
func Default() *Config {
	return &Config{
		HTTP: HTTPConfig{
			Timeout:        45 * time.Second,
			ShortTimeout:   15 * time.Second,
			MaxRetries:     3,
			RetryDelay:     2 * time.Second,
			UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			FollowRedirect: true,
		},
		DNS: DNSConfig{
			Timeout: 10 * time.Second,
			Nameservers: []string{
				"8.8.8.8:53",
				"8.8.4.4:53",
			},
		},
		TLS: TLSConfig{
			Timeout:            5 * time.Second,
			InsecureSkipVerify: true,
		},
		Scanner: ScannerConfig{
			MinCMSIndicators:       2,
			MinCMSIndicatorsNoMeta: 3,
			MaxSubdomainsDisplay:   50,
		},
	}
}
