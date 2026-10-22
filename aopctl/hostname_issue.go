package aopctl

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync/atomic"
)

// HostnameIssueRequest describes a new leaf and the hostnames to point at it.
type HostnameIssueRequest struct {
	// CACert and CAKey sign the new leaf.
	CACert *x509.Certificate
	CAKey  crypto.Signer
	// CommonName, KeyType and Days describe the leaf. The leaf must not
	// outlive the CA.
	CommonName string
	KeyType    KeyType
	Days       int
	// Hostnames are normalized with NormalizeHostnames.
	Hostnames []string
	// Progress, when set, receives CertificateUploaded and
	// AssociationRequested during Apply.
	Progress func(Event)
}

// HostnameIssuePlan is a new leaf, checked against the zone and ready to
// upload and roll out. Its accessors return copies, and Apply acts only on
// what the plan captured.
type HostnameIssuePlan struct {
	client  *Client
	leaf    *x509.Certificate
	leafPEM string
	// leafKey is encoded only for the upload. It holds a pointer, which fmt
	// prints as an address, so printing the plan does not show the key.
	leafKey    crypto.Signer
	hosts      []string
	current    map[string]*Association
	signedByCA map[string]bool
	progress   func(Event)
	applied    atomic.Bool
}

// Leaf returns a copy of the new certificate. Its key is only ever sent in
// the upload.
func (p *HostnameIssuePlan) Leaf() *x509.Certificate {
	leaf := *p.leaf
	return &leaf
}

// Hostnames returns the normalized hostnames.
func (p *HostnameIssuePlan) Hostnames() []string { return slices.Clone(p.hosts) }

// Current returns each hostname's association when planned. A nil value
// means none.
func (p *HostnameIssuePlan) Current() map[string]*Association { return cloneAssociations(p.current) }

// SignedByCA returns which of the zone's hostname certificates the CA
// signed, keyed by hostname certificate ID.
func (p *HostnameIssuePlan) SignedByCA() map[string]bool { return maps.Clone(p.signedByCA) }

// HostnameIssueResult describes a completed rollout.
type HostnameIssueResult struct {
	// CertID is the new certificate, which every listed hostname now uses.
	CertID string
	// Superseded lists the certificates the hostnames used before, in
	// hostname order. Voided and disabled associations are not counted.
	Superseded []string
}

// PlanHostnameIssue creates and checks a new leaf, then reads the zone. It
// fails without changing anything when the zone has no free certificate
// slot or a hostname has AOP disabled.
func (c *Client) PlanHostnameIssue(ctx context.Context, r HostnameIssueRequest) (*HostnameIssuePlan, error) {
	if err := checkCA(r.CACert); err != nil {
		return nil, err
	}
	if r.CAKey == nil || !keyMatchesCert(r.CACert, r.CAKey) {
		return nil, ErrKeyMismatch
	}
	hosts, err := requireHostnames(r.Hostnames)
	if err != nil {
		return nil, err
	}

	now := c.now()
	leaf, leafKey, err := createLeaf(r.CACert, r.CAKey, r.CommonName, r.KeyType, r.Days, now)
	if err != nil {
		return nil, err
	}
	if err := verifyLeaf(leaf, r.CACert, now); err != nil {
		return nil, fmt.Errorf("the new leaf does not verify against the CA: %w", err)
	}
	certs, err := c.cf.listCerts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	if len(certs) >= MaxHostnameCertificates {
		return nil, &CertificateLimitError{Count: len(certs), Limit: MaxHostnameCertificates}
	}
	signed := map[string]bool{}
	for i := range certs {
		if _, err := certSignedBy(&certs[i], r.CACert); err == nil {
			signed[certs[i].ID] = true
		}
	}
	current, err := c.readAssociations(ctx, hosts)
	if err != nil {
		return nil, err
	}
	if err := refuseDisabled(hosts, current); err != nil {
		return nil, err
	}
	return &HostnameIssuePlan{
		client:     c,
		leaf:       leaf,
		leafPEM:    EncodeCertificatePEM(leaf),
		leafKey:    leafKey,
		hosts:      hosts,
		current:    current,
		signedByCA: signed,
		progress:   r.Progress,
	}, nil
}

// Apply uploads the leaf, waits for it to become active, points every
// hostname at it and waits for each association to become active. It never
// deletes a certificate.
//
// An upload that may have created a certificate fails with
// *UploadUnknownError, and a failure after the upload with
// *HostnameRolloutError. A context that is already done fails before the
// upload, and leaves the plan unapplied. Without a deadline on ctx, Apply
// polls with no time limit.
func (p *HostnameIssuePlan) Apply(ctx context.Context) (*HostnameIssueResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("upload not sent: %w", err)
	}
	if !p.applied.CompareAndSwap(false, true) {
		return nil, ErrPlanApplied
	}
	c := p.client

	leafKeyPEM, err := EncodePrivateKeyPEM(p.leafKey)
	if err != nil {
		return nil, err
	}
	newID, err := c.cf.uploadCert(ctx, p.leafPEM, leafKeyPEM)
	// Only a Cloudflare 4xx shows that no certificate was created. A 5xx, a
	// 2xx or a response that could not be read may follow a create.
	if apiErr, ok := errors.AsType[*apiError](err); ok && (!apiErr.decoded || apiErr.status < 400 || apiErr.status > 499) {
		return nil, &UploadUnknownError{Err: err}
	}
	if err != nil {
		return nil, fmt.Errorf("upload failed: %w", err)
	}
	if newID == "" {
		return nil, &UploadUnknownError{}
	}
	emit(p.progress, CertificateUploaded{CertID: newID})

	r := &HostnameRolloutError{
		CertID:     newID,
		Hostnames:  p.Hostnames(),
		Original:   p.Current(),
		Observed:   map[string]*Association{},
		SignedByCA: p.SignedByCA(),
	}
	if err := c.rollOut(ctx, r, p.progress); err != nil {
		r.Err = err
		return nil, r
	}

	var superseded []string
	seen := map[string]bool{}
	for _, h := range p.hosts {
		if id := inUseCertID(p.current[h]); id != "" && id != newID && !seen[id] {
			seen[id] = true
			superseded = append(superseded, id)
		}
	}
	return &HostnameIssueResult{CertID: newID, Superseded: superseded}, nil
}

// rollOut points the hostnames at the uploaded certificate, recording what
// it observes in r.
func (c *Client) rollOut(ctx context.Context, r *HostnameRolloutError, progress func(Event)) error {
	if err := c.waitForCert(ctx, r.CertID); err != nil {
		// No association was changed.
		maps.Copy(r.Observed, r.Original)
		return err
	}
	emit(progress, AssociationRequested{CertID: r.CertID, Hostnames: r.Hostnames})
	r.AssociateSent = true
	if err := c.cf.associate(ctx, r.CertID, r.Hostnames); err != nil {
		// The request may have been partly applied.
		for _, h := range r.Hostnames {
			if ctx.Err() != nil {
				break
			}
			if assoc, readErr := c.cf.getAssociation(ctx, h); readErr == nil {
				r.Observed[h] = assoc
			}
		}
		return fmt.Errorf("associate hostnames: %w", err)
	}
	return c.waitForAssociations(ctx, r.CertID, r.Hostnames, r.Observed)
}
