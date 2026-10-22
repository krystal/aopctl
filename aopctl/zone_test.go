package aopctl_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

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
		if n := fake.Count(http.MethodPost, "/origin_tls_client_auth"); n != 1 {
			t.Errorf("sent %d uploads, want 1", n)
		}
	})

	t.Run("context done before the upload", func(t *testing.T) {
		c, fake, ca := zoneSetup(t)
		plan, err := c.PlanZoneIssue(context.Background(), zoneIssueRequest(ca))
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = plan.Apply(ctx)
		if _, ok := errors.AsType[*aopctl.UploadUnknownError](err); ok || !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled and not an unknown upload outcome", err)
		}
		if n := fake.Count(http.MethodPost, "/origin_tls_client_auth"); n != 0 {
			t.Errorf("sent %d uploads, want none", n)
		}
		if _, err := plan.Apply(context.Background()); err != nil {
			t.Errorf("apply after the cancelled one: %v", err)
		}
	})

	t.Run("never active", func(t *testing.T) {
		c, fake, ca := zoneSetup(t)
		fake.UploadStatuses = []string{cftest.StatusDeploymentTimedOut}
		plan, err := c.PlanZoneIssue(context.Background(), zoneIssueRequest(ca))
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		_, err = plan.Apply(context.Background())
		rolloutErr, ok := errors.AsType[*aopctl.ZoneRolloutError](err)
		if !ok || rolloutErr.CertID != cftest.ZoneCertID(101) || !rolloutErr.Enabled {
			t.Errorf("err = %#v, want a *ZoneRolloutError for the new certificate with Enabled set", err)
		}
	})
}

// TestZoneIssuePlan checks what an embedder reads from the plan: the
// certificate in use, whether the CA signed it, a key-free printout, and
// copies that cannot change the plan.
func TestZoneIssuePlan(t *testing.T) {
	c, _, ca := zoneSetup(t)
	plan, err := c.PlanZoneIssue(context.Background(), zoneIssueRequest(ca))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	zone := plan.Zone()
	inUse, ok := zone.InUse()
	if !ok || inUse == nil || inUse.ID != cftest.ZoneCertID(1) || inUse.SignedByCA {
		t.Fatalf("InUse = %+v, %v; want the other CA's certificate", inUse, ok)
	}
	if !plan.ReplacesOtherCA() {
		t.Error("ReplacesOtherCA = false, want true")
	}
	zone.Enabled = false
	zone.Certificates[0].SignedByCA = true
	if !plan.ReplacesOtherCA() || !plan.Zone().Enabled {
		t.Error("changing the returned report changed the plan")
	}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if out := fmt.Sprintf(verb, plan); strings.Contains(out, "PRIVATE KEY") {
			t.Errorf("%s of the plan shows the private key:\n%s", verb, out)
		}
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
		if err != nil {
			t.Fatalf("plan: %v", err)
		}
		// The other CA signed the certificate, so it is skipped, once.
		if skipped := plan.Skipped(); len(skipped) != 1 || skipped[0].CertID != id {
			t.Errorf("skipped = %+v, want %s once", skipped, id)
		}
	})

	for _, id := range []string{"settings", "hostnames", "../settings", ""} {
		c, fake, ca := zoneSetup(t)
		_, err := c.PlanZonePrune(context.Background(), aopctl.ZonePruneRequest{CACert: ca.cert, CertIDs: []string{id}})
		if err == nil || !strings.Contains(err.Error(), "want a UUID or 32 hex digits") {
			t.Errorf("%q: err = %v, want an invalid ID", id, err)
		}
		if n := len(fake.Recorded()); n != 0 {
			t.Errorf("%q: sent %d requests, want none", id, n)
		}
	}
}
