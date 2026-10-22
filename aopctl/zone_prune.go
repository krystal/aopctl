package aopctl

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"sync/atomic"
)

// ZonePruneRequest names the zone-level certificates to delete.
type ZonePruneRequest struct {
	// CACert must have signed each certificate.
	CACert *x509.Certificate
	// CertIDs must be UUIDs.
	CertIDs []string
	// Progress, when set, receives CertificateSkipped while planning and
	// CertificateRefused, CertificateDeleteFailed and CertificateDeleted
	// during Apply.
	Progress func(Event)
}

// ZonePrunePlan lists the zone-level certificates to delete and those
// skipped. Its accessors return copies, and Apply acts only on what the plan
// captured.
type ZonePrunePlan struct {
	client   *Client
	zone     *ZoneStatusReport
	targets  []PruneTarget
	skipped  []PruneSkip
	progress func(Event)
	applied  atomic.Bool
}

// PlanZonePrune reads the zone-level setting and certificates, and each
// named certificate. It skips certificates that are missing, already
// deleted or not signed by the CA. While zone-level AOP is enabled, it also
// skips the newest of the targets when deleting them all would leave no
// active certificate. A read that fails for another reason fails the plan.
func (c *Client) PlanZonePrune(ctx context.Context, r ZonePruneRequest) (*ZonePrunePlan, error) {
	if err := checkCA(r.CACert); err != nil {
		return nil, err
	}
	var ids []string
	for _, id := range r.CertIDs {
		if err := checkZoneCertID(id); err != nil {
			return nil, err
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	zone, err := c.readZone(ctx, r.CACert)
	if err != nil {
		return nil, err
	}

	p := &ZonePrunePlan{client: c, zone: zone, progress: r.Progress}
	skip := func(s PruneSkip) {
		p.skipped = append(p.skipped, s)
		emit(p.progress, CertificateSkipped{PruneSkip: s})
	}
	var targets []PruneTarget
	for _, id := range ids {
		cert, err := c.cf.getZoneCert(ctx, id)
		if isNotFound(err) {
			skip(PruneSkip{CertID: id, Reason: SkipNotFound})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read zone certificate %s: %w", id, err)
		}
		parsed, err := certSignedBy(cert, r.CACert)
		if err != nil {
			skip(PruneSkip{CertID: id, Reason: SkipNotSigned, Err: err})
			continue
		}
		switch cert.Status {
		case statusDeleted:
			skip(PruneSkip{CertID: id, Reason: SkipAlreadyDeleted})
			continue
		case statusPendingDeletion:
			targets = append(targets, PruneTarget{Certificate: *cert, X509: parsed, PendingDeletion: true})
			continue
		}
		targets = append(targets, PruneTarget{Certificate: *cert, X509: parsed})
	}

	keep := -1
	if zone.Enabled {
		keep = lastActiveTarget(zone, targets)
	}
	for i, t := range targets {
		if i == keep {
			skip(PruneSkip{CertID: t.ID, Reason: SkipLastActive})
			continue
		}
		p.targets = append(p.targets, t)
	}
	return p, nil
}

// lastActiveTarget returns the index of the target to keep when deleting
// every target would leave the zone without an active certificate, or -1.
// It keeps the newest active target, or the last one named when their
// upload times cannot be ordered.
func lastActiveTarget(zone *ZoneStatusReport, targets []PruneTarget) int {
	var active []int
	var certs []*Certificate
	for i, t := range targets {
		if !t.PendingDeletion && (t.Status == statusActive || zone.isActive(t.ID)) {
			active = append(active, i)
			cert := t.Certificate
			cert.Status = statusActive
			certs = append(certs, &cert)
		}
	}
	if len(active) == 0 {
		return -1
	}
	// A target already being deleted does not count as remaining.
	for _, id := range zone.activeIDs() {
		if !slices.ContainsFunc(targets, func(t PruneTarget) bool { return t.ID == id }) {
			return -1
		}
	}
	if newest, ok := newestActive(certs); ok && newest >= 0 {
		return active[newest]
	}
	return active[len(active)-1]
}

// Zone returns a copy of the zone-level setting and certificates, as
// planned.
func (p *ZonePrunePlan) Zone() *ZoneStatusReport {
	return p.zone.clone()
}

// Targets returns the certificates Apply deletes, or waits for.
func (p *ZonePrunePlan) Targets() []PruneTarget { return slices.Clone(p.targets) }

// Skipped returns the certificates that will not be deleted, in the order
// they were decided.
func (p *ZonePrunePlan) Skipped() []PruneSkip { return slices.Clone(p.skipped) }

// Deletes returns the number of delete requests Apply would send, which
// excludes certificates already being deleted.
func (p *ZonePrunePlan) Deletes() int {
	n := 0
	for _, t := range p.targets {
		if !t.PendingDeletion {
			n++
		}
	}
	return n
}

// Apply deletes each target and waits for the deletion to finish. Just
// before each delete, it reads the zone again and, while zone-level AOP is
// enabled, refuses to delete the last active certificate. It returns
// ErrNotAllDeleted, with the result, when a target was not deleted. Without
// a deadline on ctx, it polls with no time limit.
func (p *ZonePrunePlan) Apply(ctx context.Context) (*PruneResult, error) {
	if !p.applied.CompareAndSwap(false, true) {
		return nil, ErrPlanApplied
	}
	c := p.client

	res := &PruneResult{}
	failed := func(id string, err error) {
		res.NotDeleted = append(res.NotDeleted, PruneFailure{CertID: id, Err: err})
		emit(p.progress, CertificateDeleteFailed{CertID: id, Err: err})
	}
	for _, t := range p.targets {
		id := t.ID
		if !t.PendingDeletion {
			// Catch the other active certificates going away after the plan,
			// or zone-level AOP being enabled.
			zone, err := c.readZone(ctx, nil)
			if err != nil {
				failed(id, err)
				continue
			}
			if zone.Enabled && zone.isActive(id) && len(zone.activeIDs()) == 1 {
				res.NotDeleted = append(res.NotDeleted, PruneFailure{CertID: id, Reason: SkipLastActive})
				emit(p.progress, CertificateRefused{CertID: id, Reason: SkipLastActive})
				continue
			}
			if err := c.cf.deleteZoneCert(ctx, id); err != nil {
				failed(id, err)
				continue
			}
		}
		if err := c.waitForDeletion(ctx, c.cf.getZoneCert, id); err != nil {
			failed(id, err)
			continue
		}
		res.Deleted = append(res.Deleted, id)
		emit(p.progress, CertificateDeleted{CertID: id})
	}
	if len(res.NotDeleted) > 0 {
		return res, ErrNotAllDeleted
	}
	return res, nil
}
