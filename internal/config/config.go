package config

import "time"

const (
	// Default timeout values.
	defaultHTTPTimeout      = 45 * time.Second
	defaultShortTimeout     = 15 * time.Second
	defaultDNSTimeout       = 10 * time.Second
	defaultTLSTimeout       = 5 * time.Second
	defaultRetryDelay       = 2 * time.Second
	
	// Default retry settings.
	defaultMaxRetries = 3
	
	// Default CMS detection thresholds.
	defaultMinCMSIndicators       = 2
	defaultMinCMSIndicatorsNoMeta = 3
	
	// Display limits.
	defaultMaxSubdomainsDisplay = 50
	
	// Default User-Agent string.
	defaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	
	// Default DNS servers.
	googleDNS1 = "8.8.8.8:53"
	googleDNS2 = "8.8.4.4:53"
)

// Config holds application configuration.
type Config struct {
	HTTP    HTTPConfig
	DNS     DNSConfig
	TLS     TLSConfig
	Scanner ScannerConfig
}

// HTTPConfig contains HTTP client configuration.
type HTTPConfig struct {
	Timeout        time.Duration
	ShortTimeout   time.Duration
	MaxRetries     int
	RetryDelay     time.Duration
	UserAgent      string
	FollowRedirect bool
}

// DNSConfig contains DNS resolver configuration.
type DNSConfig struct {
	Timeout     time.Duration
	Nameservers []string
}

// TLSConfig contains TLS connection configuration.
type TLSConfig struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

// ScannerConfig contains scanner-specific settings.
type ScannerConfig struct {
	MinCMSIndicators       int
	MinCMSIndicatorsNoMeta int
	MaxSubdomainsDisplay   int
}

// Default returns a configuration with sensible defaults.
func Default() *Config {
	return &Config{
		HTTP: HTTPConfig{
			Timeout:        defaultHTTPTimeout,
			ShortTimeout:   defaultShortTimeout,
			MaxRetries:     defaultMaxRetries,
			RetryDelay:     defaultRetryDelay,
			UserAgent:      defaultUserAgent,
			FollowRedirect: true,
		},
		DNS: DNSConfig{
			Timeout: defaultDNSTimeout,
			Nameservers: []string{
				googleDNS1,
				googleDNS2,
			},
		},
		TLS: TLSConfig{
			Timeout:            defaultTLSTimeout,
			InsecureSkipVerify: true,
		},
		Scanner: ScannerConfig{
			MinCMSIndicators:       defaultMinCMSIndicators,
			MinCMSIndicatorsNoMeta: defaultMinCMSIndicatorsNoMeta,
			MaxSubdomainsDisplay:   defaultMaxSubdomainsDisplay,
		},
	}
}
