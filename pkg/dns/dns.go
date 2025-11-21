package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/javicosvml/rankle-go/internal/config"
	"github.com/javicosvml/rankle-go/pkg/models"
)

// Resolver handles DNS operations.
type Resolver struct {
	config   *config.Config
	resolver *net.Resolver
}

// New creates a new DNS resolver.
func New(cfg *config.Config) *Resolver {
	if cfg == nil {
		cfg = config.Default()
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: cfg.DNS.Timeout,
			}
			// Use first configured nameserver
			if len(cfg.DNS.Nameservers) > 0 {
				return d.DialContext(ctx, network, cfg.DNS.Nameservers[0])
			}
			return d.DialContext(ctx, network, address)
		},
	}

	return &Resolver{
		config:   cfg,
		resolver: resolver,
	}
}

// Analyze performs comprehensive DNS analysis.
func (r *Resolver) Analyze(domain string) (*models.DNSAnalysis, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.DNS.Timeout)
	defer cancel()

	analysis := &models.DNSAnalysis{}

	// Resolve A records
	if ips, err := r.resolver.LookupIP(ctx, "ip4", domain); err == nil {
		for _, ip := range ips {
			analysis.A = append(analysis.A, ip.String())
		}
	}

	// Resolve AAAA records
	if ips, err := r.resolver.LookupIP(ctx, "ip6", domain); err == nil {
		for _, ip := range ips {
			analysis.AAAA = append(analysis.AAAA, ip.String())
		}
	}

	// Resolve CNAME
	if cname, err := r.resolver.LookupCNAME(ctx, domain); err == nil {
		if cname != domain+"." && cname != "" {
			analysis.CNAME = append(analysis.CNAME, strings.TrimSuffix(cname, "."))
		}
	}

	// Resolve MX records
	if mxs, err := r.resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			analysis.MX = append(analysis.MX, fmt.Sprintf("%s (priority: %d)",
				strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
	}

	// Resolve NS records
	if nss, err := r.resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			analysis.NS = append(analysis.NS, strings.TrimSuffix(ns.Host, "."))
		}
	}

	// Resolve TXT records
	if txts, err := r.resolver.LookupTXT(ctx, domain); err == nil {
		analysis.TXT = txts
	}

	return analysis, nil
}

// LookupIP resolves domain to IP addresses.
func (r *Resolver) LookupIP(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.DNS.Timeout)
	defer cancel()

	ips, err := r.resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		result = append(result, ip.String())
	}

	return result, nil
}

// ReverseLookup performs reverse DNS lookup.
func (r *Resolver) ReverseLookup(ip string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.DNS.Timeout)
	defer cancel()

	return r.resolver.LookupAddr(ctx, ip)
}

// SubdomainResult represents a subdomain from crt.sh.
type SubdomainResult struct {
	NameValue string `json:"name_value"`
}

// EnumerateSubdomains discovers subdomains using Certificate Transparency logs.
func (r *Resolver) EnumerateSubdomains(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var results []SubdomainResult
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Extract unique subdomains
	subdomainMap := make(map[string]bool)
	for _, result := range results {
		subdomains := strings.Split(result.NameValue, "\n")
		for _, subdomain := range subdomains {
			subdomain = strings.TrimSpace(subdomain)
			subdomain = strings.ToLower(subdomain)
			// Skip wildcards
			if !strings.HasPrefix(subdomain, "*.") && subdomain != "" {
				subdomainMap[subdomain] = true
			}
		}
	}

	// Convert map to slice
	subdomains := make([]string, 0, len(subdomainMap))
	for subdomain := range subdomainMap {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}
