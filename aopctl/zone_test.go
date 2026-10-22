package aopctl_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/krystal/aopctl/aopctl"
	"github.com/krystal/aopctl/internal/cftest"
)

// zoneSetup has zone-level AOP enabled and one active zone certificate,
// signed by another CA.
func zoneSetup(t *testing.T) (*aopctl.Client, *cftest.Fake, *testCA) {
	t.Helper()
	c, fake, ca := setup(t, 0)
	other := newCA(t)
	fake.ZoneEnabled = true
	fake.AddZoneCert(cftest.ZoneCertID(1), cftest.IssueLeaf(t, other.cert, other.key), cftest.UploadedOn(1))
	return c, fake, ca
}

func zoneIssueRequest(ca *testCA) aopctl.ZoneIssueRequest {
	return aopctl.ZoneIssueRequest{CACert: ca.cert, CAKey: ca.key, CommonName: "leaf", KeyType: aopctl.KeyTypeECP256, Days: 30}
}

// TestZoneIssueApply guards against a retried or concurrent Apply uploading
// a second certificate, and against a done context counting as one.
func TestZoneIssueApply(t *testing.T) {
	t.Run("once", func(t *testing.T) {
		c, fake, ca := zoneSetup(t)
		ctx := context.Background()
		plan, err := c.PlanZoneIssue(ctx, zoneIssueRequest(ca))
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
		assert.Equal(t, 1, fake.Count(http.MethodPost, "/origin_tls_client_auth"), "uploads sent")
	})

	t.Run("context done before the upload", func(t *testing.T) {
		c, fake, ca := zoneSetup(t)
		plan, err := c.PlanZoneIssue(context.Background(), zoneIssueRequest(ca))
		require.NoError(t, err, "plan")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = plan.Apply(ctx)
		var unknownErr *aopctl.UploadUnknownError
		assert.NotErrorAs(t, err, &unknownErr, "want not an unknown upload outcome")
		assert.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, fake.Count(http.MethodPost, "/origin_tls_client_auth"), "uploads sent")
		_, err = plan.Apply(context.Background())
		assert.NoError(t, err, "apply after the cancelled one")
	})

	t.Run("never active", func(t *testing.T) {
		c, fake, ca := zoneSetup(t)
		fake.UploadStatuses = []string{cftest.StatusDeploymentTimedOut}
		plan, err := c.PlanZoneIssue(context.Background(), zoneIssueRequest(ca))
		require.NoError(t, err, "plan")
		_, err = plan.Apply(context.Background())
		var rolloutErr *aopctl.ZoneRolloutError
		if assert.ErrorAs(t, err, &rolloutErr) {
			assert.Equal(t, cftest.ZoneCertID(101), rolloutErr.CertID, "rollout certificate")
			assert.True(t, rolloutErr.Enabled, "rollout Enabled")
		}
	})
}

// TestZoneIssuePlan checks what an embedder reads from the plan: the
// certificate in use, whether the CA signed it, a key-free printout, and
// copies that cannot change the plan.
func TestZoneIssuePlan(t *testing.T) {
	c, _, ca := zoneSetup(t)
	plan, err := c.PlanZoneIssue(context.Background(), zoneIssueRequest(ca))
	require.NoError(t, err, "plan")
	zone := plan.Zone()
	inUse, ok := zone.InUse()
	require.True(t, ok, "InUse")
	require.NotNil(t, inUse, "InUse")
	require.Equal(t, cftest.ZoneCertID(1), inUse.ID, "InUse")
	require.False(t, inUse.SignedByCA, "InUse is signed by the CA, want the other CA's certificate")
	assert.True(t, plan.ReplacesOtherCA(), "ReplacesOtherCA")
	zone.Enabled = false
	zone.Certificates[0].SignedByCA = true
	assert.True(t, plan.ReplacesOtherCA(), "changing the returned report changed the plan")
	assert.True(t, plan.Zone().Enabled, "changing the returned report changed the plan")
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		assert.NotContains(t, fmt.Sprintf(verb, plan), "PRIVATE KEY", "%s of the plan shows the private key", verb)
	}
}

// TestZoneCertIDsChecked checks that the library, not only the command,
// keeps a zone certificate ID from reaching the settings or hostnames
// paths, and counts one certificate named in two cases once.
func TestZoneCertIDsChecked(t *testing.T) {
	t.Run("case", func(t *testing.T) {
		c, fake, ca := zoneSetup(t)
		id := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
		other := newCA(t)
		fake.AddZoneCert(id, cftest.IssueLeaf(t, other.cert, other.key), cftest.UploadedOn(2))
		plan, err := c.PlanZonePrune(context.Background(), aopctl.ZonePruneRequest{CACert: ca.cert, CertIDs: []string{strings.ToUpper(id), id}})
		require.NoError(t, err, "plan")
		// The other CA signed the certificate, so it is skipped, once.
		if skipped := plan.Skipped(); assert.Len(t, skipped, 1, "skipped") {
			assert.Equal(t, id, skipped[0].CertID, "skipped")
		}
	})

	for _, id := range []string{"settings", "hostnames", "../settings", ""} {
		c, fake, ca := zoneSetup(t)
		_, err := c.PlanZonePrune(context.Background(), aopctl.ZonePruneRequest{CACert: ca.cert, CertIDs: []string{id}})
		assert.ErrorContains(t, err, "want a UUID or 32 hex digits", "%q", id)
		assert.Empty(t, fake.Recorded(), "%q: requests sent", id)
	}
}
