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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	require.NoError(t, err, "CreateCA")
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
	require.NoError(t, err, "NewClient")
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
		require.NoError(t, err, "plan")
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
				assert.NoError(t, err, "apply")
			}
		}
		assert.Equal(t, 1, applied, "applies succeeded")
		assert.Equal(t, 1, refused, "applies refused")
		assert.Equal(t, 1, fake.Count(http.MethodPost, "/certificates"), "uploads sent")
	})

	t.Run("associate", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		ctx := context.Background()
		plan, err := c.PlanHostnameAssociate(ctx, aopctl.HostnameAssociateRequest{CACert: ca.cert, CertID: "old-1", Hostnames: []string{hostB}})
		require.NoError(t, err, "plan")
		require.NoError(t, plan.Apply(ctx), "apply")
		assert.ErrorIs(t, plan.Apply(ctx), aopctl.ErrPlanApplied, "second apply")
		assert.Equal(t, 1, fake.Count(http.MethodPut, "/hostnames"), "association requests sent")
	})

	t.Run("prune", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		fake.AddCert("spare", cftest.IssueLeaf(t, ca.cert, ca.key))
		ctx := context.Background()
		plan, err := c.PlanHostnamePrune(ctx, aopctl.HostnamePruneRequest{CACert: ca.cert, CertIDs: []string{"spare"}, Hostnames: []string{hostA}})
		require.NoError(t, err, "plan")
		_, err = plan.Apply(ctx)
		require.NoError(t, err, "apply")
		_, err = plan.Apply(ctx)
		assert.ErrorIs(t, err, aopctl.ErrPlanApplied, "second apply")
		assert.Equal(t, 1, fake.Count(http.MethodDelete, ""), "deletes sent")
	})
}

// TestHostnameIssuePlanHidesKey guards against a printed plan showing the
// leaf's private key.
func TestHostnameIssuePlanHidesKey(t *testing.T) {
	c, _, ca := setup(t, 0)
	plan, err := c.PlanHostnameIssue(context.Background(), issueRequest(ca))
	require.NoError(t, err, "plan")
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		assert.NotContains(t, fmt.Sprintf(verb, plan), "PRIVATE KEY", "%s of the plan shows the private key", verb)
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
	require.NoError(t, err, "plan")

	targets := plan.Targets()
	require.Len(t, targets, 1, "targets")
	require.Equal(t, "spare", targets[0].ID, "targets")
	// foreign was skipped as not signed by the CA, and unlisted was never
	// requested.
	targets[0].ID = "foreign"
	_ = append(targets, aopctl.PruneTarget{Certificate: aopctl.Certificate{ID: "unlisted"}})

	res, err := plan.Apply(ctx)
	require.NoError(t, err, "apply")
	var deleted []string
	for _, r := range fake.Recorded() {
		if r.Method == http.MethodDelete {
			deleted = append(deleted, r.Path[strings.LastIndex(r.Path, "/")+1:])
		}
	}
	assert.Equal(t, "spare", strings.Join(deleted, ","), "deleted")
	assert.Equal(t, "spare", strings.Join(res.Deleted, ","), "result Deleted")
}

// TestHostnameIssueFailures checks that the errors a caller recovers from
// are reachable with errors.As and errors.Is and carry the rollout state.
func TestHostnameIssueFailures(t *testing.T) {
	t.Run("mismatched CA key", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		req := issueRequest(ca)
		req.CAKey = newCA(t).key
		_, err := c.PlanHostnameIssue(context.Background(), req)
		assert.ErrorIs(t, err, aopctl.ErrKeyMismatch)
		assert.Empty(t, fake.Recorded(), "requests sent")
	})

	t.Run("context done before the upload", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		plan, err := c.PlanHostnameIssue(context.Background(), issueRequest(ca))
		require.NoError(t, err, "plan")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = plan.Apply(ctx)
		var unknownErr *aopctl.UploadUnknownError
		assert.NotErrorAs(t, err, &unknownErr, "want not an unknown upload outcome")
		assert.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, fake.Count(http.MethodPost, "/certificates"), "uploads sent")
		// Nothing was sent, so the plan can still be applied.
		_, err = plan.Apply(context.Background())
		assert.NoError(t, err, "apply after the cancelled one")
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
		var unknownErr *aopctl.UploadUnknownError
		assert.ErrorAs(t, err, &unknownErr)
	})

	t.Run("deployment timed out", func(t *testing.T) {
		c, fake, ca := setup(t, 0)
		fake.UploadStatuses = []string{cftest.StatusDeploymentTimedOut}
		_, err := apply(t, c, ca)
		var r *aopctl.HostnameRolloutError
		require.ErrorAs(t, err, &r)
		assert.Equal(t, "new-1", r.CertID, "rollout certificate")
		assert.False(t, r.AssociateSent, "rollout sent an association request")
		assert.Equal(t, "old-1 (enabled=true, status=active)", r.Observed[hostA].String(), "observed %s, want its original association", hostA)
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
		var r *aopctl.HostnameRolloutError
		require.ErrorAs(t, err, &r)
		assert.True(t, r.AssociateSent, "rollout did not send the association request")
		assert.Nil(t, r.Original[hostB], "original %s", hostB)
		if assert.NotNil(t, r.Observed[hostB], "observed %s", hostB) {
			assert.Equal(t, "new-1", r.Observed[hostB].CertID, "observed %s", hostB)
		}
		assert.True(t, r.SignedByCA["old-1"], "SignedByCA = %v, want old-1", r.SignedByCA)
	})

	t.Run("budget runs out", func(t *testing.T) {
		c, fake, ca := setup(t, 2)
		fake.UploadStatuses = []string{"pending_deployment"}
		_, err := apply(t, c, ca)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func apply(t *testing.T, c *aopctl.Client, ca *testCA) (*aopctl.HostnameIssueResult, error) {
	t.Helper()
	ctx := context.Background()
	plan, err := c.PlanHostnameIssue(ctx, issueRequest(ca))
	require.NoError(t, err, "plan")
	return plan.Apply(ctx)
}

// TestNewClientDefaults runs a whole issue with zero Options apart from
// BaseURL, so a nil HTTPClient, Now or Wait default cannot panic.
func TestNewClientDefaults(t *testing.T) {
	for _, tt := range []struct{ token, zone string }{{"", cftest.Zone}, {cftest.Token, ""}} {
		_, err := aopctl.NewClient(tt.token, tt.zone, aopctl.Options{})
		assert.Error(t, err, "NewClient(%q, %q)", tt.token, tt.zone)
	}

	fake, srv := cftest.New(t)
	// Everything is active at once, so no poll waits.
	fake.UploadStatuses = []string{cftest.StatusActive}
	fake.AssocStatuses = []string{cftest.StatusActive}
	c, err := aopctl.NewClient(cftest.Token, cftest.Zone, aopctl.Options{BaseURL: srv.URL})
	require.NoError(t, err, "NewClient")
	ca := newCA(t)
	ctx := context.Background()
	plan, err := c.PlanHostnameIssue(ctx, issueRequest(ca))
	require.NoError(t, err, "plan")
	_, err = plan.Apply(ctx)
	require.NoError(t, err, "apply")
	report, err := c.HostnameStatus(ctx, aopctl.HostnameStatusRequest{CACert: ca.cert, Hostnames: []string{hostA}})
	require.NoError(t, err, "status")
	if assert.Len(t, report.Certificates, 1, "report = %+v", report) {
		assert.True(t, report.Certificates[0].SignedByCA, "report = %+v", report)
	}
	assert.Equal(t, "new-1", report.Associations[hostA].CertID, "report = %+v", report)
}
