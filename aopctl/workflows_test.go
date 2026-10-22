package aopctl_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/krystal/aopctl/aopctl"
	"github.com/krystal/aopctl/internal/cftest"
)

const (
	hostA = "a.example.com"
	hostB = "b.example.com"
)

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	cert, key, err := aopctl.CreateCA(aopctl.CARequest{CommonName: "Test AOP CA", KeyType: aopctl.KeyTypeECP256, Days: 3650})
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// setup has hostA on old-1 and hostB with no association. Polls never wait,
// and the wait that waitLimit names reports the budget as exhausted.
func setup(t *testing.T, waitLimit int) (*aopctl.Client, *cftest.Fake, *testCA) {
	t.Helper()
	fake, srv := cftest.New(t)
	ca := newCA(t)
	fake.AddCert("old-1", cftest.IssueLeaf(t, ca.cert, ca.key))
	fake.SetAssoc(hostA, "old-1", new(true))
	waits := 0
	c, err := aopctl.NewClient(cftest.Token, cftest.Zone, aopctl.Options{
		BaseURL: srv.URL,
		Wait: func(ctx context.Context, _ time.Duration) error {
			waits++
			if waitLimit > 0 && waits >= waitLimit {
				return context.DeadlineExceeded
			}
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, fake, ca
}

func issueRequest(ca *testCA) aopctl.HostnameIssueRequest {
	return aopctl.HostnameIssueRequest{
		CACert: ca.cert, CAKey: ca.key,
		CommonName: "leaf", KeyType: aopctl.KeyTypeECP256, Days: 30,
		Hostnames: []string{hostA, hostB},
	}
}

// TestPlansApplyOnce guards against a retried or concurrent Apply repeating
// its writes, such as uploading a second certificate.
func TestPlansApplyOnce(t *testing.T) {
	t.Run("issue", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		ctx := context.Background()
		plan, err := c.PlanHostnameIssue(ctx, issueRequest(ca))
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		errs := make(chan error, 2)
		for range 2 {
			go func() {
				_, err := plan.Apply(ctx)
				errs <- err
			}()
		}
		var applied, refused int
		for range 2 {
			switch err := <-errs; {
			case err == nil:
				applied++
			case errors.Is(err, aopctl.ErrPlanApplied):
				refused++
			default:
				t.Errorf("apply: %v", err)
			}
		}
		if applied != 1 || refused != 1 {
			t.Errorf("%d applies succeeded and %d were refused, want 1 and 1", applied, refused)
		}
		if n := fake.Count(http.MethodPost, "/certificates"); n != 1 {
			t.Errorf("sent %d uploads, want 1", n)
		}
	})

	t.Run("associate", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		ctx := context.Background()
		plan, err := c.PlanHostnameAssociate(ctx, aopctl.HostnameAssociateRequest{CACert: ca.cert, CertID: "old-1", Hostnames: []string{hostB}})
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		if err := plan.Apply(ctx); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if err := plan.Apply(ctx); !errors.Is(err, aopctl.ErrPlanApplied) {
			t.Errorf("second apply: err = %v, want ErrPlanApplied", err)
		}
		if n := fake.Count(http.MethodPut, "/hostnames"); n != 1 {
			t.Errorf("sent %d association requests, want 1", n)
		}
	})

	t.Run("prune", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		fake.AddCert("spare", cftest.IssueLeaf(t, ca.cert, ca.key))
		ctx := context.Background()
		plan, err := c.PlanHostnamePrune(ctx, aopctl.HostnamePruneRequest{CACert: ca.cert, CertIDs: []string{"spare"}, Hostnames: []string{hostA}})
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		if _, err := plan.Apply(ctx); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if _, err := plan.Apply(ctx); !errors.Is(err, aopctl.ErrPlanApplied) {
			t.Errorf("second apply: err = %v, want ErrPlanApplied", err)
		}
		if n := fake.Count(http.MethodDelete, ""); n != 1 {
			t.Errorf("sent %d deletes, want 1", n)
		}
	})
}

// TestHostnameIssuePlanHidesKey guards against a printed plan showing the
// leaf's private key.
func TestHostnameIssuePlanHidesKey(t *testing.T) {
	c, _, ca := setup(t, 0)
	plan, err := c.PlanHostnameIssue(context.Background(), issueRequest(ca))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, plan); strings.Contains(out, "PRIVATE KEY") {
			t.Errorf("%s of the plan shows the private key:\n%s", verb, out)
		}
	}
}

// TestHostnamePruneAccessorsCopy checks that changing what an accessor
// returns cannot change what Apply deletes.
func TestHostnamePruneAccessorsCopy(t *testing.T) {
	c, fake, ca := setup(t, 0)
	fake.AddCert("spare", cftest.IssueLeaf(t, ca.cert, ca.key))
	other := newCA(t)
	fake.AddCert("foreign", cftest.IssueLeaf(t, other.cert, other.key))
	fake.AddCert("unlisted", cftest.IssueLeaf(t, ca.cert, ca.key))
	ctx := context.Background()
	plan, err := c.PlanHostnamePrune(ctx, aopctl.HostnamePruneRequest{
		CACert: ca.cert, CertIDs: []string{"spare", "foreign"}, Hostnames: []string{hostA},
	})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	targets := plan.Targets()
	if len(targets) != 1 || targets[0].ID != "spare" {
		t.Fatalf("targets = %+v, want spare only", targets)
	}
	// foreign was skipped as not signed by the CA, and unlisted was never
	// requested.
	targets[0].ID = "foreign"
	_ = append(targets, aopctl.PruneTarget{Certificate: aopctl.Certificate{ID: "unlisted"}})

	res, err := plan.Apply(ctx)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	var deleted []string
	for _, r := range fake.Recorded() {
		if r.Method == http.MethodDelete {
			deleted = append(deleted, r.Path[strings.LastIndex(r.Path, "/")+1:])
		}
	}
	if strings.Join(deleted, ",") != "spare" || strings.Join(res.Deleted, ",") != "spare" {
		t.Errorf("deleted %v (result %v), want spare only", deleted, res.Deleted)
	}
}

// TestHostnameIssueFailures checks that the errors a caller recovers from
// are reachable with errors.As and errors.Is and carry the rollout state.
func TestHostnameIssueFailures(t *testing.T) {
	t.Run("mismatched CA key", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		req := issueRequest(ca)
		req.CAKey = newCA(t).key
		if _, err := c.PlanHostnameIssue(context.Background(), req); !errors.Is(err, aopctl.ErrKeyMismatch) {
			t.Errorf("err = %v, want ErrKeyMismatch", err)
		}
		if n := len(fake.Recorded()); n != 0 {
			t.Errorf("sent %d requests, want none", n)
		}
	})

	t.Run("context done before the upload", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		plan, err := c.PlanHostnameIssue(context.Background(), issueRequest(ca))
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = plan.Apply(ctx)
		if _, ok := errors.AsType[*aopctl.UploadUnknownError](err); ok || !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled and not an unknown upload outcome", err)
		}
		if n := fake.Count(http.MethodPost, "/certificates"); n != 0 {
			t.Errorf("sent %d uploads, want none", n)
		}
		// Nothing was sent, so the plan can still be applied.
		if _, err := plan.Apply(context.Background()); err != nil {
			t.Errorf("apply after the cancelled one: %v", err)
		}
	})

	t.Run("upload server error", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
			return true
		}
		_, err := apply(t, c, ca)
		if _, ok := errors.AsType[*aopctl.UploadUnknownError](err); !ok {
			t.Errorf("err = %v, want *UploadUnknownError", err)
		}
	})

	t.Run("deployment timed out", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		fake.UploadStatuses = []string{cftest.StatusDeploymentTimedOut}
		_, err := apply(t, c, ca)
		r, ok := errors.AsType[*aopctl.HostnameRolloutError](err)
		if !ok {
			t.Fatalf("err = %v, want *HostnameRolloutError", err)
		}
		if r.CertID != "new-1" || r.AssociateSent {
			t.Errorf("rollout = %+v, want new-1 without an association request", r)
		}
		if got := r.Observed[hostA].String(); got != "old-1 (enabled=true, status=active)" {
			t.Errorf("observed %s = %s, want its original association", hostA, got)
		}
	})

	t.Run("association partly applied", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPut {
				return false
			}
			fake.ApplyAssociation(hostB, "new-1", new(true))
			cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
			return true
		}
		_, err := apply(t, c, ca)
		r, ok := errors.AsType[*aopctl.HostnameRolloutError](err)
		if !ok {
			t.Fatalf("err = %v, want *HostnameRolloutError", err)
		}
		if !r.AssociateSent || r.Original[hostB] != nil || r.Observed[hostB] == nil || r.Observed[hostB].CertID != "new-1" {
			t.Errorf("rollout = %+v, want the request sent and %s observed on new-1", r, hostB)
		}
		if !r.SignedByCA["old-1"] {
			t.Errorf("SignedByCA = %v, want old-1", r.SignedByCA)
		}
	})

	t.Run("budget runs out", func(t *testing.T) {
		c, fake, ca := setup(t, 2)
		fake.UploadStatuses = []string{"pending_deployment"}
		_, err := apply(t, c, ca)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want it to wrap context.DeadlineExceeded", err)
		}
	})
}

func apply(t *testing.T, c *aopctl.Client, ca *testCA) (*aopctl.HostnameIssueResult, error) {
	t.Helper()
	ctx := context.Background()
	plan, err := c.PlanHostnameIssue(ctx, issueRequest(ca))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return plan.Apply(ctx)
}

// TestNewClientDefaults runs a whole issue with zero Options apart from
// BaseURL, so a nil HTTPClient, Now or Wait default cannot panic.
func TestNewClientDefaults(t *testing.T) {
	for _, tt := range []struct{ token, zone string }{{"", cftest.Zone}, {cftest.Token, ""}} {
		if _, err := aopctl.NewClient(tt.token, tt.zone, aopctl.Options{}); err == nil {
			t.Errorf("NewClient(%q, %q) succeeded, want an error", tt.token, tt.zone)
		}
	}

	fake, srv := cftest.New(t)
	// Everything is active at once, so no poll waits.
	fake.UploadStatuses = []string{cftest.StatusActive}
	fake.AssocStatuses = []string{cftest.StatusActive}
	c, err := aopctl.NewClient(cftest.Token, cftest.Zone, aopctl.Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ca := newCA(t)
	ctx := context.Background()
	plan, err := c.PlanHostnameIssue(ctx, issueRequest(ca))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if _, err := plan.Apply(ctx); err != nil {
		t.Fatalf("apply: %v", err)
	}
	report, err := c.HostnameStatus(ctx, aopctl.HostnameStatusRequest{CACert: ca.cert, Hostnames: []string{hostA}})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(report.Certificates) != 1 || !report.Certificates[0].SignedByCA || report.Associations[hostA].CertID != "new-1" {
		t.Errorf("report = %+v", report)
	}
}
