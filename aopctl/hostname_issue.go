package aopctl

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
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
// upload and roll out.
type HostnameIssuePlan struct {
	// Leaf is the new certificate. Its key is only ever sent in the upload.
	Leaf      *x509.Certificate
	Hostnames []string
	// Current holds each hostname's association when planned. A nil value
	// means none.
	Current map[string]*Association
	// SignedByCA records which of the zone's hostname certificates the CA
	// signed, keyed by hostname certificate ID.
	SignedByCA map[string]bool

	client     *Client
	leafKeyPEM string
	progress   func(Event)
	applied    bool
}

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
	leafKeyPEM, err := EncodePrivateKeyPEM(leafKey)
	if err != nil {
		return nil, err
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
		Leaf:       leaf,
		Hostnames:  hosts,
		Current:    current,
		SignedByCA: signed,
		client:     c,
		leafKeyPEM: leafKeyPEM,
		progress:   r.Progress,
	}, nil
}

// Apply uploads the leaf, waits for it to become active, points every
// hostname at it and waits for each association to become active. It never
// deletes a certificate.
//
// An upload that may have created a certificate fails with
// *UploadUnknownError, and a failure after the upload with
// *HostnameRolloutError.
func (p *HostnameIssuePlan) Apply(ctx context.Context) (*HostnameIssueResult, error) {
	if p.applied {
		return nil, ErrPlanApplied
	}
	p.applied = true
	c := p.client

	newID, err := c.cf.uploadCert(ctx, EncodeCertificatePEM(p.Leaf), p.leafKeyPEM)
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
		Hostnames:  p.Hostnames,
		Original:   p.Current,
		Observed:   map[string]*Association{},
		SignedByCA: p.SignedByCA,
	}
	if err := c.rollOut(ctx, r, p.progress); err != nil {
		r.Err = err
		return nil, r
	}

	var superseded []string
	seen := map[string]bool{}
	for _, h := range p.Hostnames {
		if id := inUseCertID(p.Current[h]); id != "" && id != newID && !seen[id] {
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
