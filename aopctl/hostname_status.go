package aopctl

import (
	"context"
	"crypto/x509"
	"fmt"
)

// HostnameStatusRequest names the hostnames to report on.
type HostnameStatusRequest struct {
	// CACert, when set, is checked against each certificate.
	CACert *x509.Certificate
	// Hostnames are normalized with NormalizeHostnames, and may be empty.
	Hostnames []string
}

// HostnameStatusReport lists the zone's hostname certificates and the
// listed hostnames' associations. The associations of hostnames that were
// not listed cannot be discovered through the Cloudflare API.
type HostnameStatusReport struct {
	Certificates []CertificateInfo
	Hostnames    []string
	// Associations holds each hostname's association. A nil value means
	// none.
	Associations map[string]*Association
}

// CertificateInfo describes one of the zone's hostname certificates.
type CertificateInfo struct {
	Certificate
	// X509 is the parsed certificate, or nil when X509Err is set.
	X509    *x509.Certificate
	X509Err error
	// SignedByCA is false when the request had no CACert.
	SignedByCA bool
	// UsedBy lists the hostnames whose association points at the
	// certificate, including disabled ones but not voided ones.
	UsedBy []string
}

// HostnameStatus reads the zone's hostname certificates and the hostnames'
// associations.
func (c *Client) HostnameStatus(ctx context.Context, r HostnameStatusRequest) (*HostnameStatusReport, error) {
	if r.CACert != nil {
		if err := checkCA(r.CACert); err != nil {
			return nil, err
		}
	}
	hosts, err := NormalizeHostnames(r.Hostnames)
	if err != nil {
		return nil, err
	}
	certs, err := c.cf.listCerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	assocs, err := c.readAssociations(ctx, hosts)
	if err != nil {
		return nil, err
	}

	report := &HostnameStatusReport{Hostnames: hosts, Associations: assocs}
	for _, cert := range certs {
		info := CertificateInfo{Certificate: cert, UsedBy: hostsUsing(hosts, assocs, cert.ID)}
		info.X509, info.X509Err = ParseCertificatePEM(cert.PEM)
		if r.CACert != nil && info.X509 != nil {
			info.SignedByCA = info.X509.CheckSignatureFrom(r.CACert) == nil
		}
		report.Certificates = append(report.Certificates, info)
	}
	return report, nil
}
