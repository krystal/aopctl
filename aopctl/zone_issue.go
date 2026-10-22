package aopctl

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
)

// ZoneIssueRequest describes a new zone-level leaf.
type ZoneIssueRequest struct {
	// CACert and CAKey sign the new leaf.
	CACert *x509.Certificate
	CAKey  crypto.Signer
	// CommonName, KeyType and Days describe the leaf. The leaf must not
	// outlive the CA.
	CommonName string
	KeyType    KeyType
	Days       int
	// Progress, when set, receives CertificateUploaded during Apply.
	Progress func(Event)
}

// ZoneIssuePlan is a new zone-level leaf, checked against the zone and
// ready to upload. Its accessors return copies, and Apply acts only on what
// the plan captured.
type ZoneIssuePlan struct {
	client  *Client
	leaf    *x509.Certificate
	leafPEM string
	// leafKey is encoded only for the upload. It holds a pointer, which fmt
	// prints as an address, so printing the plan does not show the key.
	leafKey  crypto.Signer
	zone     *ZoneStatusReport
	progress func(Event)
	applied  atomic.Bool
}

// ZoneIssueResult describes an uploaded certificate that became active.
type ZoneIssueResult struct {
	// CertID is the new certificate.
	CertID string
	// Superseded lists the certificates that were active when planned.
	// While zone-level AOP is enabled, Cloudflare no longer uses them.
	Superseded []string
}

// PlanZoneIssue creates and checks a new leaf, then reads the zone-level
// setting and certificates. Cloudflare documents no limit on zone-level
// certificates, so none is checked.
func (c *Client) PlanZoneIssue(ctx context.Context, r ZoneIssueRequest) (*ZoneIssuePlan, error) {
	if err := checkCA(r.CACert); err != nil {
		return nil, err
	}
	if r.CAKey == nil || !keyMatchesCert(r.CACert, r.CAKey) {
		return nil, ErrKeyMismatch
	}
	now := c.now()
	leaf, leafKey, err := createLeaf(r.CACert, r.CAKey, r.CommonName, r.KeyType, r.Days, now)
	if err != nil {
		return nil, err
	}
	if err := verifyLeaf(leaf, r.CACert, now); err != nil {
		return nil, fmt.Errorf("the new leaf does not verify against the CA: %w", err)
	}
	zone, err := c.readZone(ctx, r.CACert)
	if err != nil {
		return nil, err
	}
	return &ZoneIssuePlan{
		client:   c,
		leaf:     leaf,
		leafPEM:  EncodeCertificatePEM(leaf),
		leafKey:  leafKey,
		zone:     zone,
		progress: r.Progress,
	}, nil
}

// Leaf returns a copy of the new certificate. Its key is only ever sent in
// the upload.
func (p *ZoneIssuePlan) Leaf() *x509.Certificate {
	leaf := *p.leaf
	return &leaf
}

// Zone returns a copy of the zone-level setting and certificates, as
// planned. Its InUse method returns the certificate Cloudflare uses now, as
// derived, and whether the CA signed it.
func (p *ZoneIssuePlan) Zone() *ZoneStatusReport {
	return p.zone.clone()
}

// ReplacesOtherCA reports whether the new certificate takes over from one
// the CA did not sign: zone-level AOP is enabled, and the certificate
// Cloudflare uses is not signed by the CA or cannot be derived. Once the
// new certificate is active, Cloudflare presents it to every origin without
// a per-hostname certificate, and origins that trust only the other CA
// reject it.
func (p *ZoneIssuePlan) ReplacesOtherCA() bool {
	inUse, ok := p.zone.InUse()
	return !ok || (inUse != nil && !inUse.SignedByCA)
}

// Apply uploads the leaf and waits for it to become active. It never
// deletes a certificate and never changes the zone-level AOP setting.
//
// An upload that may have created a certificate fails with
// *UploadUnknownError, and a certificate that does not become active with
// *ZoneRolloutError. A context that is already done fails before the
// upload, and leaves the plan unapplied. Without a deadline on ctx, Apply
// polls with no time limit.
func (p *ZoneIssuePlan) Apply(ctx context.Context) (*ZoneIssueResult, error) {
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
	newID, err := c.cf.uploadZoneCert(ctx, p.leafPEM, leafKeyPEM)
	if err != nil {
		return nil, uploadError(err)
	}
	switch {
	case newID == "":
		return nil, &UploadUnknownError{}
	case !ValidZoneCertID(newID):
		return nil, &UploadUnknownError{Err: errors.New("the response has an invalid certificate ID")}
	}
	emit(p.progress, CertificateUploaded{CertID: newID})

	if err := c.waitForCert(ctx, c.cf.getZoneCert, newID); err != nil {
		return nil, &ZoneRolloutError{CertID: newID, Enabled: p.zone.Enabled, Err: err}
	}
	return &ZoneIssueResult{CertID: newID, Superseded: p.zone.activeIDs()}, nil
}
