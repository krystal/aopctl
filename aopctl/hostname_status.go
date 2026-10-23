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
	// Hostnames are normalized with NormalizeHostnames. There may be none,
	// and at most MaxHostnames.
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

// CertificateInfo describes one of the zone's hostname or zone-level
// certificates.
type CertificateInfo struct {
	Certificate
	// X509 is the parsed certificate, or nil when X509Err is set.
	X509    *x509.Certificate
	X509Err error
	// SignedByCA is false when the request had no CACert.
	SignedByCA bool
	// UsedBy lists the hostnames whose association points at a hostname
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
	hosts, err := limitHostnames(r.Hostnames)
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
		info := certificateInfo(cert, r.CACert)
		info.UsedBy = hostsUsing(hosts, assocs, cert.ID)
		report.Certificates = append(report.Certificates, info)
	}
	return report, nil
}
