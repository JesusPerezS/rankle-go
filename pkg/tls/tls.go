package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/javicosvml/rankle-go/internal/config"
	"github.com/javicosvml/rankle-go/pkg/models"
)

// Analyzer handles TLS/SSL certificate analysis
type Analyzer struct {
	config *config.Config
}

// New creates a new TLS analyzer
func New(cfg *config.Config) *Analyzer {
	if cfg == nil {
		cfg = config.Default()
	}
	return &Analyzer{config: cfg}
}

// Analyze performs TLS certificate analysis
func (a *Analyzer) Analyze(domain string) (*models.TLSAnalysis, error) {
	dialer := &net.Dialer{
		Timeout: a.config.TLS.Timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: a.config.TLS.InsecureSkipVerify,
		ServerName:         domain,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cert := state.PeerCertificates[0]

	analysis := &models.TLSAnalysis{
		Version:      tlsVersionString(state.Version),
		CipherSuite:  tls.CipherSuiteName(state.CipherSuite),
		Issuer:       cert.Issuer.CommonName,
		Subject:      cert.Subject.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SANs:         cert.DNSNames,
		SignatureAlg: cert.SignatureAlgorithm.String(),
		PublicKeyAlg: cert.PublicKeyAlgorithm.String(),
	}

	return analysis, nil
}

// GetCertificate retrieves the TLS certificate
func (a *Analyzer) GetCertificate(domain string) (*x509.Certificate, error) {
	dialer := &net.Dialer{
		Timeout: a.config.TLS.Timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: a.config.TLS.InsecureSkipVerify,
		ServerName:         domain,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certs[0], nil
}

// ValidateCertificate checks if the certificate is valid
func (a *Analyzer) ValidateCertificate(cert *x509.Certificate, domain string) error {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired")
	}

	opts := x509.VerifyOptions{
		DNSName: domain,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// tlsVersionString converts TLS version uint16 to string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
