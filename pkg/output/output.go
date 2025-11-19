package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/javicosvml/rankle-go/pkg/models"
)

// Formatter handles output formatting
type Formatter struct{}

// New creates a new output formatter
func New() *Formatter {
	return &Formatter{}
}

// PrintBanner displays the application banner
func (f *Formatter) PrintBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗  █████╗ ███╗   ██╗██╗  ██╗██╗     ███████╗                     ║
║   ██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝██║     ██╔════╝                     ║
║   ██████╔╝███████║██╔██╗ ██║█████╔╝ ██║     █████╗                       ║
║   ██╔══██╗██╔══██║██║╚██╗██║██╔═██╗ ██║     ██╔══╝                       ║
║   ██║  ██║██║  ██║██║ ╚████║██║  ██╗███████╗███████╗                     ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚══════╝                     ║
║                                                                           ║
║              Web Infrastructure Reconnaissance Tool                       ║
║          Named after Rankle, Master of Pranks (MTG)                      ║
║                                                                           ║
║                      100%% Open Source - No API Keys                      ║
║                         Written in Go for Performance                     ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

// PrintSummary displays a summary of scan results
func (f *Formatter) PrintSummary(result *models.ScanResult) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("📊 SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\n🎯 Domain:          %s\n", result.Domain)
	fmt.Printf("🕐 Timestamp:       %s\n", result.Timestamp.Format(time.RFC1123))

	if result.HTTP != nil {
		fmt.Printf("\n🌐 HTTP Status:     %d\n", result.HTTP.StatusCode)
		fmt.Printf("⚡ Response Time:   %dms\n", result.HTTP.ResponseTime)
		if result.HTTP.Server != "" {
			fmt.Printf("🖥️  Server:          %s\n", result.HTTP.Server)
		}
	}

	if result.DNS != nil && len(result.DNS.A) > 0 {
		fmt.Printf("\n🔍 IP Address:      %s\n", result.DNS.A[0])
	}

	if result.Technologies != nil {
		if result.Technologies.CMS != "" {
			fmt.Printf("📦 CMS:             %s\n", result.Technologies.CMS)
		}
		if len(result.Technologies.Libraries) > 0 {
			fmt.Printf("📚 Libraries:       %s\n", strings.Join(result.Technologies.Libraries, ", "))
		}
	}

	if result.CDN != "" {
		fmt.Printf("🌐 CDN:             %s\n", result.CDN)
	}

	if result.WAF != "" {
		fmt.Printf("🛡️  WAF:             %s\n", result.WAF)
	}

	if result.CloudProvider != "" {
		fmt.Printf("☁️  Cloud Provider:  %s\n", result.CloudProvider)
	}

	if result.Geolocation != nil {
		fmt.Printf("\n🌍 Location:        %s, %s\n", result.Geolocation.City, result.Geolocation.Country)
		if result.Geolocation.ISP != "" {
			fmt.Printf("🏢 ISP:             %s\n", result.Geolocation.ISP)
		}
	}

	if result.TLS != nil {
		fmt.Printf("\n🔐 TLS Version:     %s\n", result.TLS.Version)
		fmt.Printf("📜 Certificate:     %s\n", result.TLS.Subject)
		fmt.Printf("   Expires:         %s\n", result.TLS.NotAfter.Format("2006-01-02"))
	}

	if len(result.Subdomains) > 0 {
		fmt.Printf("\n🔎 Subdomains:      %d found\n", len(result.Subdomains))
	}

	fmt.Println(strings.Repeat("=", 80))
}

// SaveJSON saves results as JSON file
func (f *Formatter) SaveJSON(result *models.ScanResult, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("\n✅ JSON report saved: %s\n", outputPath)
	return nil
}

// SaveText saves results as human-readable text file
func (f *Formatter) SaveText(result *models.ScanResult, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Build text report
	var sb strings.Builder
	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString("RANKLE - Web Infrastructure Reconnaissance Report\n")
	sb.WriteString(strings.Repeat("=", 80) + "\n\n")
	sb.WriteString(fmt.Sprintf("Domain:      %s\n", result.Domain))
	sb.WriteString(fmt.Sprintf("Scan Date:   %s\n", result.Timestamp.Format(time.RFC1123)))
	sb.WriteString(strings.Repeat("=", 80) + "\n\n")

	// HTTP Section
	if result.HTTP != nil {
		sb.WriteString("HTTP ANALYSIS\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		sb.WriteString(fmt.Sprintf("Status Code:    %d\n", result.HTTP.StatusCode))
		sb.WriteString(fmt.Sprintf("Response Time:  %dms\n", result.HTTP.ResponseTime))
		if result.HTTP.Server != "" {
			sb.WriteString(fmt.Sprintf("Server:         %s\n", result.HTTP.Server))
		}
		if result.HTTP.ContentType != "" {
			sb.WriteString(fmt.Sprintf("Content-Type:   %s\n", result.HTTP.ContentType))
		}
		sb.WriteString("\n")
	}

	// DNS Section
	if result.DNS != nil {
		sb.WriteString("DNS RECORDS\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		if len(result.DNS.A) > 0 {
			sb.WriteString(fmt.Sprintf("A Records:      %s\n", strings.Join(result.DNS.A, ", ")))
		}
		if len(result.DNS.AAAA) > 0 {
			sb.WriteString(fmt.Sprintf("AAAA Records:   %s\n", strings.Join(result.DNS.AAAA, ", ")))
		}
		if len(result.DNS.CNAME) > 0 {
			sb.WriteString(fmt.Sprintf("CNAME:          %s\n", strings.Join(result.DNS.CNAME, ", ")))
		}
		if len(result.DNS.MX) > 0 {
			sb.WriteString(fmt.Sprintf("MX Records:     %s\n", strings.Join(result.DNS.MX, ", ")))
		}
		if len(result.DNS.NS) > 0 {
			sb.WriteString(fmt.Sprintf("NS Records:     %s\n", strings.Join(result.DNS.NS, ", ")))
		}
		sb.WriteString("\n")
	}

	// Technologies Section
	if result.Technologies != nil {
		sb.WriteString("DETECTED TECHNOLOGIES\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		if result.Technologies.CMS != "" {
			sb.WriteString(fmt.Sprintf("CMS:            %s\n", result.Technologies.CMS))
		}
		if len(result.Technologies.Libraries) > 0 {
			sb.WriteString(fmt.Sprintf("Libraries:      %s\n", strings.Join(result.Technologies.Libraries, ", ")))
		}
		if len(result.Technologies.Frameworks) > 0 {
			sb.WriteString(fmt.Sprintf("Frameworks:     %s\n", strings.Join(result.Technologies.Frameworks, ", ")))
		}
		sb.WriteString("\n")
	}

	// Infrastructure Section
	sb.WriteString("INFRASTRUCTURE\n")
	sb.WriteString(strings.Repeat("-", 40) + "\n")
	if result.CDN != "" {
		sb.WriteString(fmt.Sprintf("CDN:            %s\n", result.CDN))
	}
	if result.WAF != "" {
		sb.WriteString(fmt.Sprintf("WAF:            %s\n", result.WAF))
	}
	if result.CloudProvider != "" {
		sb.WriteString(fmt.Sprintf("Cloud:          %s\n", result.CloudProvider))
	}
	sb.WriteString("\n")

	// TLS Section
	if result.TLS != nil {
		sb.WriteString("TLS/SSL CERTIFICATE\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		sb.WriteString(fmt.Sprintf("TLS Version:    %s\n", result.TLS.Version))
		sb.WriteString(fmt.Sprintf("Subject:        %s\n", result.TLS.Subject))
		sb.WriteString(fmt.Sprintf("Issuer:         %s\n", result.TLS.Issuer))
		sb.WriteString(fmt.Sprintf("Valid From:     %s\n", result.TLS.NotBefore.Format("2006-01-02")))
		sb.WriteString(fmt.Sprintf("Valid Until:    %s\n", result.TLS.NotAfter.Format("2006-01-02")))
		sb.WriteString("\n")
	}

	// Geolocation Section
	if result.Geolocation != nil {
		sb.WriteString("GEOLOCATION\n")
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		sb.WriteString(fmt.Sprintf("Country:        %s\n", result.Geolocation.Country))
		sb.WriteString(fmt.Sprintf("City:           %s\n", result.Geolocation.City))
		if result.Geolocation.ISP != "" {
			sb.WriteString(fmt.Sprintf("ISP:            %s\n", result.Geolocation.ISP))
		}
		sb.WriteString("\n")
	}

	// Subdomains Section
	if len(result.Subdomains) > 0 {
		sb.WriteString(fmt.Sprintf("SUBDOMAINS (%d found)\n", len(result.Subdomains)))
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		for i, subdomain := range result.Subdomains {
			if i >= 50 { // Limit display
				sb.WriteString(fmt.Sprintf("... and %d more\n", len(result.Subdomains)-50))
				break
			}
			sb.WriteString(fmt.Sprintf("  - %s\n", subdomain))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(strings.Repeat("=", 80) + "\n")
	sb.WriteString("Generated by Rankle - https://github.com/javicosvml/rankle-go\n")

	// Write to file
	if err := os.WriteFile(outputPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	fmt.Printf("\n✅ Text report saved: %s\n", outputPath)
	return nil
}
