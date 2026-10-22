package aopctl

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Cloudflare's limits.
const (
	// MaxHostnames is the number of hostnames a certificate can serve.
	MaxHostnames = 100
	// MaxHostnameCertificates is the number of hostname certificates a
	// zone can hold.
	MaxHostnameCertificates = 10
)

// NormalizeHostnames lowercases the hostnames and strips surrounding
// whitespace and a trailing dot, skipping empty ones and duplicates. It
// rejects wildcards, ports, paths, inner whitespace and more than
// MaxHostnames hostnames.
func NormalizeHostnames(raw []string) ([]string, error) {
	seen := map[string]bool{}
	var hosts []string
	for _, entry := range raw {
		host := strings.TrimRight(strings.ToLower(strings.TrimSpace(entry)), ".")
		if host == "" {
			continue
		}
		if !validHostname(host) {
			return nil, fmt.Errorf("invalid hostname %q: want an exact hostname", entry)
		}
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	if len(hosts) > MaxHostnames {
		return nil, fmt.Errorf("%d hostnames given: a certificate can serve at most %d", len(hosts), MaxHostnames)
	}
	return hosts, nil
}

func validHostname(host string) bool {
	if strings.ContainsAny(host, "*:/,") {
		return false
	}
	for i := 0; i < len(host); i++ {
		if host[i] < 0x21 || host[i] > 0x7e {
			return false
		}
	}
	return true
}

// requireHostnames normalizes the hostnames and rejects an empty list.
func requireHostnames(raw []string) ([]string, error) {
	hosts, err := NormalizeHostnames(raw)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, errors.New("no hostnames")
	}
	return hosts, nil
}

var certIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// ValidHostnameCertID reports whether id is safe to use as a hostname
// certificate ID in a request path: one to 64 letters, digits and hyphens,
// so it cannot change the path. It does not check that id is a UUID, as
// Cloudflare's IDs are.
func ValidHostnameCertID(id string) bool {
	return certIDPattern.MatchString(id)
}

func checkHostnameCertID(id string) error {
	if !ValidHostnameCertID(id) {
		return fmt.Errorf("invalid certificate ID %q", id)
	}
	return nil
}

// readAssociations reads each hostname's association; a nil entry means none.
// Any error other than "no association" aborts.
func (c *Client) readAssociations(ctx context.Context, hosts []string) (map[string]*Association, error) {
	assocs := make(map[string]*Association, len(hosts))
	for _, h := range hosts {
		assoc, err := c.cf.getAssociation(ctx, h)
		if err != nil {
			return nil, fmt.Errorf("read association for %s: %w", h, err)
		}
		assocs[h] = assoc
	}
	return assocs, nil
}

// refuseDisabled stops a write that would re-enable AOP for a hostname
// someone disabled on purpose.
func refuseDisabled(hosts []string, assocs map[string]*Association) error {
	for _, h := range hosts {
		if assoc := assocs[h]; assoc != nil && assoc.Enabled != nil && !*assoc.Enabled {
			return fmt.Errorf("%s has AOP disabled (enabled=false) for certificate %s: re-enable it in Cloudflare or remove it from the hostname list", h, assoc.CertID)
		}
	}
	return nil
}

// inUseCertID returns the certificate a hostname uses, or "" when its
// association is missing or voided.
func inUseCertID(assoc *Association) string {
	if assoc == nil || assoc.Enabled == nil || !*assoc.Enabled {
		return ""
	}
	return assoc.CertID
}

// hostsUsing lists the hostnames whose association points at id. Disabled
// associations count; voided ones do not.
func hostsUsing(hosts []string, assocs map[string]*Association, id string) []string {
	var using []string
	for _, h := range hosts {
		if assoc := assocs[h]; assoc != nil && assoc.Enabled != nil && assoc.CertID == id {
			using = append(using, h)
		}
	}
	return using
}

// certSignedBy parses a Cloudflare certificate and checks the CA signed it.
func certSignedBy(cert *Certificate, ca *x509.Certificate) (*x509.Certificate, error) {
	parsed, err := ParseCertificatePEM(cert.PEM)
	if err != nil {
		return nil, fmt.Errorf("certificate %s: %w", cert.ID, err)
	}
	if err := parsed.CheckSignatureFrom(ca); err != nil {
		return nil, &NotSignedError{CertID: cert.ID}
	}
	return parsed, nil
}
