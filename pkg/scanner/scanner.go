package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/javicosvml/rankle-go/internal/config"
	"github.com/javicosvml/rankle-go/pkg/models"
)

// Scanner handles the main scanning logic.
type Scanner struct {
	config *config.Config
	client *http.Client
}

// New creates a new Scanner with the given configuration.
func New(cfg *config.Config) *Scanner {
	if cfg == nil {
		cfg = config.Default()
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	client := &http.Client{
		Timeout:   cfg.HTTP.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !cfg.HTTP.FollowRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	return &Scanner{
		config: cfg,
		client: client,
	}
}

// Scan performs a complete scan of the domain.
func (s *Scanner) Scan(domain string) (*models.ScanResult, error) {
	result := &models.ScanResult{
		Domain:    domain,
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Ensure domain has proper format
	domain = s.normalizeDomain(domain)
	result.Domain = domain

	return result, nil
}

// AnalyzeHTTP performs HTTP analysis.
func (s *Scanner) AnalyzeHTTP(domain string) (*models.HTTPAnalysis, *http.Response, error) {
	url := s.ensureHTTPS(domain)

	ctx, cancel := context.WithTimeout(context.Background(), s.config.HTTP.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", s.config.HTTP.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	start := time.Now()
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	responseTime := time.Since(start).Milliseconds()

	headers := make(map[string]string)
	for key, values := range resp.Header {
		headers[strings.ToLower(key)] = strings.Join(values, ", ")
	}

	analysis := &models.HTTPAnalysis{
		StatusCode:   resp.StatusCode,
		Server:       resp.Header.Get("Server"),
		Headers:      headers,
		ResponseTime: responseTime,
		ContentType:  resp.Header.Get("Content-Type"),
	}

	// Check for redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		analysis.RedirectURL = resp.Header.Get("Location")
	}

	return analysis, resp, nil
}

// GetHTMLBody reads and returns the response body as string.
func (s *Scanner) GetHTMLBody(resp *http.Response) (string, error) {
	if resp == nil {
		return "", fmt.Errorf("response is nil")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}

// normalizeDomain removes protocol and port from domain.
func (s *Scanner) normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	return domain
}

// ensureHTTPS adds https:// protocol if missing.
func (s *Scanner) ensureHTTPS(domain string) string {
	domain = s.normalizeDomain(domain)
	return "https://" + domain
}

// GetClient returns the HTTP client.
func (s *Scanner) GetClient() *http.Client {
	return s.client
}

// GetConfig returns the scanner configuration.
func (s *Scanner) GetConfig() *config.Config {
	return s.config
}
