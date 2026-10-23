package aopctl_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/krystal/aopctl/aopctl"
	"github.com/krystal/aopctl/internal/cftest"
)

// euZone is the ID of eu.example.com, a subdomain zone of the fake's zone.
const euZone = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

func zoneFinder(t *testing.T) (*aopctl.ZoneFinder, *cftest.Fake) {
	t.Helper()
	fake, srv := cftest.New(t)
	fake.AddZone(euZone, "eu.example.com")
	f, err := aopctl.NewZoneFinder(cftest.Token, aopctl.Options{BaseURL: srv.URL})
	require.NoError(t, err, "NewZoneFinder")
	return f, fake
}

// zoneLookups returns the names List Zones was asked for, in order.
func zoneLookups(fake *cftest.Fake) []string {
	var names []string
	for _, r := range fake.Recorded() {
		if r.Method == http.MethodGet && r.Path == "/zones" {
			q, _ := url.ParseQuery(r.Query)
			names = append(names, q.Get("name"))
		}
	}
	return names
}

func TestHostnameZone(t *testing.T) {
	tests := []struct {
		host     string
		wantID   string
		wantName string
	}{
		{"app.eu.example.com", euZone, "eu.example.com"},
		{"a.b.eu.example.com", euZone, "eu.example.com"},
		{"eu.example.com", euZone, "eu.example.com"},
		{"app.example.com", cftest.Zone, "example.com"},
		{"example.com", cftest.Zone, "example.com"},
		{" App.Example.COM. ", cftest.Zone, "example.com"},
		// A suffix counts only at a label boundary.
		{"neu.example.com", cftest.Zone, "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			f, _ := zoneFinder(t)
			zone, err := f.HostnameZone(context.Background(), tt.host)
			require.NoError(t, err, "HostnameZone")
			assert.Equal(t, aopctl.Zone{ID: tt.wantID, Name: tt.wantName}, zone, "zone")
		})
	}
}

func TestHostnameZoneLookups(t *testing.T) {
	f, fake := zoneFinder(t)
	ctx := context.Background()
	_, err := f.HostnameZone(ctx, "app.eu.example.com")
	require.NoError(t, err, "HostnameZone")
	assert.Equal(t, []string{"app.eu.example.com", "eu.example.com"}, zoneLookups(fake), "lookups, want longest first and none after the match")
	q, err := url.ParseQuery(fake.Recorded()[0].Query)
	require.NoError(t, err, "query")
	assert.Equal(t, "active", q.Get("status"), "status filter")

	for _, host := range []string{"a.example.com", "b.example.com", "a.example.com", "b.eu.example.com"} {
		_, err := f.HostnameZone(ctx, host)
		require.NoError(t, err, "HostnameZone(%s)", host)
	}
	assert.Equal(t, []string{"app.eu.example.com", "eu.example.com", "a.example.com", "example.com", "b.example.com", "b.eu.example.com"},
		zoneLookups(fake), "lookups, want each name once")
}

func TestHostnameZoneNoMatch(t *testing.T) {
	for _, host := range []string{"app.example.org", "localhost"} {
		t.Run(host, func(t *testing.T) {
			f, _ := zoneFinder(t)
			_, err := f.HostnameZone(context.Background(), host)
			var matchErr *aopctl.ZoneMatchError
			require.ErrorAs(t, err, &matchErr)
			assert.Equal(t, aopctl.ZoneMatchError{Hostname: host}, *matchErr, "error")
			assert.EqualError(t, err, "no active zone matches hostname "+host)
		})
	}

	t.Run("too long", func(t *testing.T) {
		f, fake := zoneFinder(t)
		_, err := f.HostnameZone(context.Background(), strings.Repeat("a.", 127)+"com")
		assert.ErrorContains(t, err, "longer than 253 bytes")
		assert.Empty(t, fake.Recorded(), "requests sent")
	})
}

func TestZoneAmbiguous(t *testing.T) {
	const other = "0123456789abcdef0123456789abcdef"
	t.Run("hostname", func(t *testing.T) {
		f, fake := zoneFinder(t)
		fake.Zones = append(fake.Zones, cftest.ZoneEntry{ID: other, Name: "example.com", Status: cftest.StatusActive})
		_, err := f.HostnameZone(context.Background(), "app.example.com")
		var matchErr *aopctl.ZoneMatchError
		require.ErrorAs(t, err, &matchErr)
		assert.Equal(t, aopctl.ZoneMatchError{Hostname: "app.example.com", Name: "example.com", Matches: 2}, *matchErr, "error")
		assert.EqualError(t, err, "hostname app.example.com matches 2 active zones named example.com")
	})

	t.Run("name", func(t *testing.T) {
		f, fake := zoneFinder(t)
		fake.Zones = append(fake.Zones, cftest.ZoneEntry{ID: other, Name: "example.com", Status: cftest.StatusActive})
		_, err := f.ZoneNamed(context.Background(), "example.com")
		assert.EqualError(t, err, "2 active zones are named example.com")
	})

	t.Run("inactive duplicate", func(t *testing.T) {
		f, fake := zoneFinder(t)
		fake.Zones = append(fake.Zones, cftest.ZoneEntry{ID: other, Name: "example.com", Status: "pending"})
		zone, err := f.HostnameZone(context.Background(), "app.example.com")
		require.NoError(t, err, "HostnameZone")
		assert.Equal(t, cftest.Zone, zone.ID, "zone ID")
	})
}

// TestZoneListIgnoredFilter guards against a List Zones response that
// ignores the filters picking the wrong zone.
func TestZoneListIgnoredFilter(t *testing.T) {
	unfiltered := func(fake *cftest.Fake, totalPages int) {
		fake.Zones = append(fake.Zones, cftest.ZoneEntry{ID: "0123456789abcdef0123456789abcdef", Name: "eu.example.com", Status: "moved"})
		fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.URL.Path != "/zones" {
				return false
			}
			var all []any
			for _, z := range fake.Zones {
				all = append(all, map[string]any{"id": z.ID, "name": z.Name, "status": z.Status})
			}
			cftest.WriteEnvelope(w, http.StatusOK, all, map[string]any{"result_info": map[string]any{"page": 1, "total_pages": totalPages}})
			return true
		}
	}

	t.Run("one page", func(t *testing.T) {
		f, fake := zoneFinder(t)
		unfiltered(fake, 1)
		zone, err := f.HostnameZone(context.Background(), "app.eu.example.com")
		require.NoError(t, err, "HostnameZone")
		assert.Equal(t, aopctl.Zone{ID: euZone, Name: "eu.example.com"}, zone, "zone")
	})

	t.Run("more pages", func(t *testing.T) {
		f, fake := zoneFinder(t)
		unfiltered(fake, 2)
		_, err := f.HostnameZone(context.Background(), "app.eu.example.com")
		assert.ErrorContains(t, err, "the list has 2 pages, want one")
		assert.Len(t, zoneLookups(fake), 1, "lookups, want none after the failed one")
	})
}

// TestZoneLookupFailure guards against a failed lookup of a subdomain zone
// letting its parent zone match.
func TestZoneLookupFailure(t *testing.T) {
	f, fake := zoneFinder(t)
	fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.URL.Path != "/zones" || r.URL.Query().Get("name") != "eu.example.com" {
			return false
		}
		cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
		return true
	}
	ctx := context.Background()
	_, err := f.HostnameZone(ctx, "app.eu.example.com")
	assert.ErrorContains(t, err, "find the zone of app.eu.example.com: list zones named eu.example.com: GET /zones: HTTP 500")
	var matchErr *aopctl.ZoneMatchError
	assert.NotErrorAs(t, err, &matchErr)
	assert.Equal(t, []string{"app.eu.example.com", "eu.example.com"}, zoneLookups(fake), "lookups, want none of example.com")

	// The failure is not cached.
	fake.Hook = nil
	zone, err := f.HostnameZone(ctx, "app.eu.example.com")
	require.NoError(t, err, "HostnameZone after the failure")
	assert.Equal(t, euZone, zone.ID, "zone ID")
}

func TestZoneListForbidden(t *testing.T) {
	for _, tt := range []struct {
		name  string
		write func(w http.ResponseWriter)
	}{
		{"envelope", func(w http.ResponseWriter) {
			cftest.WriteAPIError(w, http.StatusForbidden, 10000, "Authentication error")
		}},
		{"not an envelope", func(w http.ResponseWriter) {
			cftest.WriteRaw(w, http.StatusForbidden, "text/html", "<html>Forbidden</html>")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, fake := zoneFinder(t)
			fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
				if r.URL.Path != "/zones" {
					return false
				}
				tt.write(w)
				return true
			}
			_, err := f.HostnameZone(context.Background(), "app.example.com")
			assert.ErrorIs(t, err, aopctl.ErrZoneListForbidden)
			assert.ErrorContains(t, err, "HTTP 403")
			_, err = f.ZoneNamed(context.Background(), "example.com")
			assert.ErrorIs(t, err, aopctl.ErrZoneListForbidden)
		})
	}
}

func TestZoneNamed(t *testing.T) {
	f, _ := zoneFinder(t)
	ctx := context.Background()
	zone, err := f.ZoneNamed(ctx, "EU.example.com.")
	require.NoError(t, err, "ZoneNamed")
	assert.Equal(t, aopctl.Zone{ID: euZone, Name: "eu.example.com"}, zone, "zone")

	_, err = f.ZoneNamed(ctx, "app.example.com")
	var matchErr *aopctl.ZoneMatchError
	require.ErrorAs(t, err, &matchErr)
	assert.Equal(t, aopctl.ZoneMatchError{Name: "app.example.com"}, *matchErr, "error")
	assert.EqualError(t, err, "no active zone is named app.example.com")
}

func TestZoneByID(t *testing.T) {
	f, fake := zoneFinder(t)
	ctx := context.Background()
	zone, err := f.Zone(ctx, euZone)
	require.NoError(t, err, "Zone")
	assert.Equal(t, aopctl.Zone{ID: euZone, Name: "eu.example.com"}, zone, "zone")

	before := len(fake.Recorded())
	_, err = f.Zone(ctx, "eu.example.com")
	assert.ErrorContains(t, err, "invalid zone ID")
	assert.Len(t, fake.Recorded(), before, "requests sent for an invalid ID")

	fake.Zones = append(fake.Zones, cftest.ZoneEntry{ID: "0123456789abcdef0123456789abcdef", Name: "new.example.com", Status: "pending"})
	_, err = f.Zone(ctx, "0123456789abcdef0123456789abcdef")
	assert.EqualError(t, err, `zone new.example.com is not active: its status is "pending"`)

	_, err = f.Zone(ctx, strings.Repeat("f", 32))
	assert.ErrorContains(t, err, "HTTP 404")
	assert.NotContains(t, err.Error(), strings.Repeat("f", 32), "error shows the zone ID")
}

func TestNewZoneFinder(t *testing.T) {
	_, err := aopctl.NewZoneFinder("", aopctl.Options{})
	assert.Error(t, err, "NewZoneFinder without a token")
}

// TestHostnameLimit checks that the hostname workflows, unlike
// NormalizeHostnames, take at most MaxHostnames hostnames.
func TestHostnameLimit(t *testing.T) {
	hosts := make([]string, aopctl.MaxHostnames+1)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("h%d.example.com", i)
	}
	normalized, err := aopctl.NormalizeHostnames(hosts)
	require.NoError(t, err, "NormalizeHostnames")
	assert.Len(t, normalized, aopctl.MaxHostnames+1, "normalized hostnames")

	c, fake, ca := setup(t, 0)
	ctx := context.Background()
	req := issueRequest(ca)
	req.Hostnames = hosts
	_, err = c.PlanHostnameIssue(ctx, req)
	assert.EqualError(t, err, "101 hostnames given: a certificate can serve at most 100", "PlanHostnameIssue")
	_, err = c.PlanHostnameAssociate(ctx, aopctl.HostnameAssociateRequest{CACert: ca.cert, CertID: "old-1", Hostnames: hosts})
	assert.EqualError(t, err, "101 hostnames given: a certificate can serve at most 100", "PlanHostnameAssociate")
	_, err = c.PlanHostnamePrune(ctx, aopctl.HostnamePruneRequest{CACert: ca.cert, CertIDs: []string{"old-1"}, Hostnames: hosts})
	assert.EqualError(t, err, "101 hostnames given: a certificate can serve at most 100", "PlanHostnamePrune")
	_, err = c.HostnameStatus(ctx, aopctl.HostnameStatusRequest{Hostnames: hosts})
	assert.EqualError(t, err, "101 hostnames given: a certificate can serve at most 100", "HostnameStatus")
	assert.Empty(t, fake.Recorded(), "requests sent")

	_, err = c.HostnameStatus(ctx, aopctl.HostnameStatusRequest{Hostnames: hosts[:aopctl.MaxHostnames]})
	assert.NoError(t, err, "HostnameStatus with MaxHostnames hostnames")
}
