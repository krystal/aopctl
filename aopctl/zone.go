package aopctl

import (
	"context"
	"crypto/x509"
	"fmt"
	"regexp"
	"slices"
	"time"
)

var zoneCertIDPattern = regexp.MustCompile(`(?i)^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

// ValidZoneCertID reports whether id is a UUID, with or without dashes:
// 32 hex digits, in either case. Cloudflare's API reference shows
// identifiers in both forms. A zone certificate's path shares its prefix
// with the zone's settings and hostname paths, and a hex ID can name
// neither, so no other ID is used in a path.
func ValidZoneCertID(id string) bool {
	return zoneCertIDPattern.MatchString(id)
}

func checkZoneCertID(id string) error {
	if !ValidZoneCertID(id) {
		return fmt.Errorf("invalid zone certificate ID %q: want a UUID or 32 hex digits", id)
	}
	return nil
}

// ZoneStatusRequest configures ZoneStatus.
type ZoneStatusRequest struct {
	// CACert, when set, is checked against each certificate.
	CACert *x509.Certificate
}

// ZoneStatusReport is the zone-level AOP configuration: the setting and the
// zone-level certificates. Per-hostname certificates override it for their
// hostnames.
type ZoneStatusReport struct {
	// Enabled is the zone-level AOP setting. It is separate from the zone's
	// global AOP setting, which aopctl neither reads nor changes.
	Enabled bool
	// Certificates lists the zone-level certificates in Cloudflare's
	// order. UsedBy is always empty.
	Certificates []CertificateInfo
}

// NewestActive returns the active certificate with the latest uploaded_on.
// Cloudflare's docs say that when several certificates are active, it uses
// the most recently deployed one, so this derives the certificate Cloudflare
// uses while zone-level AOP is enabled. The API does not report it.
//
// It returns nil and true when no certificate is active, and nil and false
// when the active certificates cannot be ordered because one has a missing
// or unreadable uploaded_on, or two share the latest.
func (r *ZoneStatusReport) NewestActive() (*CertificateInfo, bool) {
	certs := make([]*Certificate, len(r.Certificates))
	for i := range r.Certificates {
		certs[i] = &r.Certificates[i].Certificate
	}
	i, ok := newestActive(certs)
	if i < 0 {
		return nil, ok
	}
	return &r.Certificates[i], true
}

// InUse returns NewestActive while zone-level AOP is enabled, and nil and
// true while it is disabled.
func (r *ZoneStatusReport) InUse() (*CertificateInfo, bool) {
	if !r.Enabled {
		return nil, true
	}
	return r.NewestActive()
}

// clone copies the report, so a plan's own copy cannot change.
func (r *ZoneStatusReport) clone() *ZoneStatusReport {
	c := *r
	c.Certificates = slices.Clone(r.Certificates)
	for i, cert := range c.Certificates {
		if cert.Enabled != nil {
			c.Certificates[i].Enabled = new(*cert.Enabled)
		}
	}
	return &c
}

// newestActive returns the index of the active certificate with the latest
// uploaded_on, or -1. It reports false when the order is unknown.
func newestActive(certs []*Certificate) (int, bool) {
	newest := -1
	var newestAt time.Time
	tie := false
	for i, cert := range certs {
		if cert.Status != statusActive {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, cert.UploadedOn)
		if err != nil {
			return -1, false
		}
		switch {
		case newest < 0 || at.After(newestAt):
			newest, newestAt, tie = i, at, false
		case at.Equal(newestAt):
			tie = true
		}
	}
	if tie {
		return -1, false
	}
	return newest, true
}

// ZoneStatus reads the zone-level AOP setting and certificates.
func (c *Client) ZoneStatus(ctx context.Context, r ZoneStatusRequest) (*ZoneStatusReport, error) {
	if r.CACert != nil {
		if err := checkCA(r.CACert); err != nil {
			return nil, err
		}
	}
	return c.readZone(ctx, r.CACert)
}

// readZone reads the setting and certificates, checking each certificate
// against ca when it is set.
func (c *Client) readZone(ctx context.Context, ca *x509.Certificate) (*ZoneStatusReport, error) {
	enabled, err := c.cf.getZoneSetting(ctx)
	if err != nil {
		return nil, fmt.Errorf("read zone-level AOP setting: %w", err)
	}
	certs, err := c.cf.listZoneCerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list zone certificates: %w", err)
	}
	report := &ZoneStatusReport{Enabled: enabled}
	for _, cert := range certs {
		report.Certificates = append(report.Certificates, certificateInfo(cert, ca))
	}
	return report, nil
}

// certificateInfo parses the certificate and, when ca is set, checks that
// it signed it.
func certificateInfo(cert Certificate, ca *x509.Certificate) CertificateInfo {
	info := CertificateInfo{Certificate: cert}
	info.X509, info.X509Err = ParseCertificatePEM(cert.PEM)
	if ca != nil && info.X509 != nil {
		info.SignedByCA = info.X509.CheckSignatureFrom(ca) == nil
	}
	return info
}

// isActive reports whether the zone has an active certificate with the ID.
func (r *ZoneStatusReport) isActive(id string) bool {
	for _, cert := range r.Certificates {
		if cert.ID == id {
			return cert.Status == statusActive
		}
	}
	return false
}

// activeIDs lists the active certificates.
func (r *ZoneStatusReport) activeIDs() []string {
	var ids []string
	for _, cert := range r.Certificates {
		if cert.Status == statusActive {
			ids = append(ids, cert.ID)
		}
	}
	return ids
}
