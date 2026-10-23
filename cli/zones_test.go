package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/krystal/aopctl/internal/cftest"
)

const (
	// euZone is the ID of eu.example.com, a subdomain zone of the fake's
	// zone, example.com.
	euZone = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	euA    = "a.eu.example.com"
	euB    = "b.eu.example.com"
)

// lookupHarness has no CLOUDFLARE_ZONE_ID, so hostname commands look up
// each hostname's zone: example.com, whose AOP state is h.fake's, or
// eu.example.com, whose AOP state the returned fake holds.
func lookupHarness(t *testing.T) (*harness, *cftest.Fake) {
	t.Helper()
	h := newHarness(t)
	delete(h.env, "CLOUDFLARE_ZONE_ID")
	return h, h.fake.AddZone(euZone, "eu.example.com")
}

// zoneRequests returns the requests that look up zones rather than use a
// zone's AOP endpoints.
func zoneRequests(h *harness) []cftest.Request {
	var reqs []cftest.Request
	for _, r := range h.fake.Recorded() {
		if !strings.Contains(r.Path, "/origin_tls_client_auth") {
			reqs = append(reqs, r)
		}
	}
	return reqs
}

// aopRequests returns the requests to any zone's AOP endpoints.
func aopRequests(h *harness) []cftest.Request {
	var reqs []cftest.Request
	for _, r := range h.fake.Recorded() {
		if strings.Contains(r.Path, "/origin_tls_client_auth") {
			reqs = append(reqs, r)
		}
	}
	return reqs
}

// forbidZoneLookups answers every zone lookup with a 403, as for a token
// without Zone > Zone > Read, and passes other requests to next, unless it
// is nil.
func forbidZoneLookups(h *harness, next func(w http.ResponseWriter, r *http.Request, body []byte) bool) {
	h.fake.Hook = func(w http.ResponseWriter, r *http.Request, body []byte) bool {
		if !strings.Contains(r.URL.Path, "/origin_tls_client_auth") {
			cftest.WriteAPIError(w, http.StatusForbidden, 10000, "Authentication error")
			return true
		}
		return next != nil && next(w, r, body)
	}
}

// TestZoneFromEnv checks that with CLOUDFLARE_ZONE_ID set, hostname
// commands look nothing up and print what they printed before zones were
// looked up, with or without a --zone of the same ID.
func TestZoneFromEnv(t *testing.T) {
	h := issueHarness(t)
	forbidZoneLookups(h, nil)

	code, status, stderr := h.run("hostname", "status")
	require.Equal(t, 0, code, "status: exit code; stderr:\n%s", stderr)
	assert.NotContains(t, status, "Zone:", "status")
	code, sameZone, stderr := h.run("hostname", "status", "--zone", strings.ToUpper(cftest.Zone))
	require.Equal(t, 0, code, "status --zone: exit code; stderr:\n%s", stderr)
	assert.Equal(t, status, sameZone, "status --zone with CLOUDFLARE_ZONE_ID's ID")

	code, _, stderr = h.run("hostname", "issue", "--dry-run", "--zone", cftest.Zone)
	require.Equal(t, 0, code, "issue: exit code; stderr:\n%s", stderr)
	assert.NotContains(t, stderr, "Zone:", "issue plan")
	assert.Empty(t, zoneRequests(h), "zone lookups")
}

// TestZoneFromEnvRecovery re-runs a printed recovery command, which carries
// --zone, with a token that cannot list zones: CLOUDFLARE_ZONE_ID makes the
// lookup unnecessary, so the command must still work.
func TestZoneFromEnvRecovery(t *testing.T) {
	h := issueHarness(t)
	forbidZoneLookups(h, func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodPut {
			return false
		}
		cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
		return true
	})
	code, _, stderr := h.run("hostname", "issue")
	require.Equal(t, 1, code, "issue: exit code; stderr:\n%s", stderr)
	resume := commandLines(stderr, "aopctl hostname associate"+zoneOpt+" --cert-id new-1")
	require.Len(t, resume, 1, "resume commands; stderr:\n%s", stderr)

	forbidZoneLookups(h, nil)
	code, _, stderr = h.run(resume[0]...)
	require.Equal(t, 0, code, "resume: exit code; stderr:\n%s", stderr)
	for _, host := range []string{hostA, hostB, hostC, hostD} {
		assert.Equal(t, "new-1", h.fake.AssocCertID(host), "%s association", host)
	}
	assert.Empty(t, zoneRequests(h), "zone lookups")
}

func TestZoneLookupIssue(t *testing.T) {
	h, _ := lookupHarness(t)
	h.fake.AddCert("old-1", h.ca.issue(t))
	h.fake.SetAssoc(hostA, "old-1", new(true))
	h.env["AOP_HOSTNAMES"] = hostA + "," + hostB

	code, stdout, stderr := h.run("hostname", "issue")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	assert.True(t, strings.HasPrefix(stderr, "Zone: example.com ("+cftest.Zone+")\nNew leaf:\n"), "stderr does not start with the zone:\n%s", stderr)
	assert.Contains(t, stdout, "  aopctl hostname prune"+zoneOpt+" --cert-id old-1 --hostname a.example.com --hostname b.example.com\n")
	for _, r := range h.fake.Writes() {
		assert.True(t, strings.HasPrefix(r.Path, "/zones/"+cftest.Zone+"/"), "%s %s, want a write to the fake's zone", r.Method, r.Path)
	}
	assert.Equal(t, "new-1", h.fake.AssocCertID(hostB), "%s association", hostB)
}

func TestZoneGroupedStatus(t *testing.T) {
	h, eu := lookupHarness(t)
	h.fake.AddCert("main-1", h.ca.issue(t))
	h.fake.SetAssoc(hostA, "main-1", new(true))
	eu.AddCert("eu-1", h.ca.issue(t))
	eu.SetAssoc(euA, "eu-1", new(true))
	h.env["AOP_HOSTNAMES"] = strings.Join([]string{hostA, euA, hostB}, ",")

	code, stdout, stderr := h.run("hostname", "status")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	main, euPart, ok := strings.Cut(stdout, "\n\nZone: eu.example.com ("+euZone+")\n")
	require.True(t, ok, "no eu.example.com section after a blank line:\n%s", stdout)
	assert.True(t, strings.HasPrefix(main, "Zone: example.com ("+cftest.Zone+")\nCertificates (1 of 10):\n  main-1\n"), "example.com section:\n%s", main)
	for _, want := range []string{hostA + ": main-1", hostB + ": none"} {
		assert.Contains(t, main, want, "example.com section")
	}
	assert.NotContains(t, main, "eu", "example.com section")
	assert.True(t, strings.HasPrefix(euPart, "Certificates (1 of 10):\n  eu-1\n"), "eu.example.com section:\n%s", euPart)
	assert.Contains(t, euPart, euA+": eu-1", "eu.example.com section")
	assert.NotContains(t, euPart, "main-1", "eu.example.com section")
	assert.NotContains(t, euPart, hostA+":", "eu.example.com section")
	assert.Equal(t, 1, strings.Count(stdout, "cannot be discovered"), "closing notes")
}

func TestZoneMultiZoneWrites(t *testing.T) {
	for _, args := range [][]string{
		{"hostname", "issue"},
		{"hostname", "associate", "--cert-id", "eu-1"},
		{"hostname", "prune", "--cert-id", "eu-1", "--yes"},
	} {
		t.Run(args[1], func(t *testing.T) {
			h, eu := lookupHarness(t)
			eu.AddCert("eu-1", h.ca.issue(t))
			h.env["AOP_HOSTNAMES"] = strings.Join([]string{hostA, euA, hostB}, ",")
			code, stdout, stderr := h.run(args...)
			require.Equal(t, 2, code, "exit code; stderr:\n%s", stderr)
			want := "aopctl: the hostnames are in 2 zones, and hostname " + args[1] + " changes one zone at a time:\n" +
				"  example.com (" + cftest.Zone + "): 2 hostname(s)\n" +
				"  eu.example.com (" + euZone + "): 1 hostname(s)\n" +
				"Pass --zone to pick one.\n"
			assert.Equal(t, want, stderr, "stderr")
			assert.Empty(t, stdout, "stdout")
			assert.Empty(t, aopRequests(h), "AOP requests sent")
		})
	}
}

func TestZoneFilter(t *testing.T) {
	setup := func(t *testing.T) (*harness, *cftest.Fake) {
		h, eu := lookupHarness(t)
		h.fake.AddCert("old-1", h.ca.issue(t))
		h.fake.SetAssoc(hostA, "old-1", new(true))
		h.env["AOP_HOSTNAMES"] = strings.Join([]string{hostA, euA, hostB, euB}, ",")
		return h, eu
	}
	planned := func(stderr string) []string {
		var hosts []string
		for line := range strings.SplitSeq(stderr, "\n") {
			if host, _, ok := strings.Cut(strings.TrimSpace(line), ": "); ok && strings.HasSuffix(line, "-> new") {
				hosts = append(hosts, host)
			}
		}
		return hosts
	}
	for _, tt := range []struct {
		zone string
		want []string
	}{
		// a.eu.example.com ends with example.com but is in the subdomain
		// zone.
		{"example.com", []string{hostA, hostB}},
		{"eu.example.com", []string{euA, euB}},
		{euZone, []string{euA, euB}},
	} {
		t.Run(tt.zone, func(t *testing.T) {
			h, _ := setup(t)
			code, _, stderr := h.run("hostname", "issue", "--dry-run", "--zone", tt.zone)
			require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
			assert.Equal(t, tt.want, planned(stderr), "planned hostnames")
			assert.Empty(t, h.fake.Writes(), "write requests")
		})
	}

	t.Run("apply", func(t *testing.T) {
		h, eu := setup(t)
		code, stdout, stderr := h.run("hostname", "issue", "--zone", "eu.example.com")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		writes := h.fake.Writes()
		require.NotEmpty(t, writes, "write requests")
		for _, r := range writes {
			assert.True(t, strings.HasPrefix(r.Path, "/zones/"+euZone+"/"), "%s %s, want a write to eu.example.com", r.Method, r.Path)
			if r.Method != http.MethodPut {
				continue
			}
			var put struct {
				Config []struct {
					Hostname string `json:"hostname"`
				} `json:"config"`
			}
			require.NoError(t, json.Unmarshal(r.Body, &put), "PUT body")
			var hosts []string
			for _, c := range put.Config {
				hosts = append(hosts, c.Hostname)
			}
			assert.Equal(t, []string{euA, euB}, hosts, "PUT hostnames")
		}
		for _, host := range []string{euA, euB} {
			assert.Equal(t, "new-1", eu.AssocCertID(host), "%s association", host)
		}
		assert.Equal(t, "old-1", h.fake.AssocCertID(hostA), "%s association", hostA)
		assert.Empty(t, h.fake.AssocCertID(hostB), "%s association", hostB)
		assert.Contains(t, stdout, "The listed hostnames now use certificate new-1.")
	})
}

func TestZoneOutOfZoneHostname(t *testing.T) {
	for _, tt := range []struct {
		zone, host string
	}{
		{"eu.example.com", hostA},
		// The hostname ends with the zone's name but is in a subdomain zone.
		{"example.com", euA},
	} {
		t.Run(tt.zone+" "+tt.host, func(t *testing.T) {
			h, _ := lookupHarness(t)
			code, stdout, stderr := h.run("hostname", "issue", "--zone", tt.zone, "--hostname", tt.host)
			assert.Equal(t, 2, code, "exit code; stderr:\n%s", stderr)
			assert.Equal(t, "aopctl: --hostname "+tt.host+" is not in zone "+tt.zone+"\n", stderr, "stderr")
			assert.Empty(t, stdout, "stdout")
			assert.Empty(t, aopRequests(h), "AOP requests sent")
		})
	}

	t.Run("none of AOP_HOSTNAMES", func(t *testing.T) {
		h, _ := lookupHarness(t)
		h.env["AOP_HOSTNAMES"] = hostA
		code, _, stderr := h.run("hostname", "issue", "--zone", "eu.example.com")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, "aopctl: none of the hostnames in AOP_HOSTNAMES is in zone eu.example.com\n", stderr, "stderr")
		assert.Empty(t, aopRequests(h), "AOP requests sent")
	})
}

func TestZoneCommandsNeedZone(t *testing.T) {
	for _, args := range [][]string{
		{"zone", "status"},
		{"zone", "issue", "--dry-run"},
		{"zone", "enable", "--dry-run"},
		{"zone", "prune", "--cert-id", zoneOld, "--dry-run"},
	} {
		t.Run(args[1], func(t *testing.T) {
			h, _ := lookupHarness(t)
			h.env["AOP_HOSTNAMES"] = hostA
			code, _, stderr := h.run(args...)
			assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
			assert.Equal(t, "aopctl: no zone: pass --zone or set CLOUDFLARE_ZONE_ID\n", stderr, "stderr")
			assert.Empty(t, h.fake.Recorded(), "requests sent")
		})
	}

	t.Run("zone name", func(t *testing.T) {
		h, _ := lookupHarness(t)
		code, stdout, stderr := h.run("zone", "status", "--zone", "example.com")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Len(t, zoneRequests(h), 1, "zone lookups")
		assert.Contains(t, stdout, "see aopctl hostname status"+zoneOpt+" too")
	})

	t.Run("zone ID", func(t *testing.T) {
		h, eu := lookupHarness(t)
		eu.ZoneEnabled = true
		forbidZoneLookups(h, nil)
		code, stdout, stderr := h.run("zone", "status", "--zone", euZone)
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stdout, "Zone-level AOP: enabled", "eu.example.com's setting")
		assert.Empty(t, zoneRequests(h), "zone lookups")
	})
}

func TestZoneHostnameLimit(t *testing.T) {
	hosts := func(n int, zone string) []string {
		hosts := make([]string, n)
		for i := range hosts {
			hosts[i] = fmt.Sprintf("h%d.%s", i, zone)
		}
		return hosts
	}

	t.Run("per zone", func(t *testing.T) {
		h, _ := lookupHarness(t)
		h.env["AOP_HOSTNAMES"] = strings.Join(append(hosts(100, "example.com"), hosts(50, "eu.example.com")...), ",")
		code, stdout, stderr := h.run("hostname", "status")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stdout, "h99.example.com: none")
		assert.Contains(t, stdout, "h49.eu.example.com: none")
	})

	t.Run("over in one zone", func(t *testing.T) {
		h, _ := lookupHarness(t)
		h.env["AOP_HOSTNAMES"] = strings.Join(append(hosts(101, "example.com"), hosts(50, "eu.example.com")...), ",")
		code, _, stderr := h.run("hostname", "issue", "--zone", "example.com")
		assert.Equal(t, 2, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, "aopctl: 101 hostnames in zone example.com: a certificate can serve at most 100\n", stderr, "stderr")
		assert.Empty(t, aopRequests(h), "AOP requests sent")
	})
}

func TestZoneLookupErrors(t *testing.T) {
	const skip = "To skip the lookup, set CLOUDFLARE_ZONE_ID, or pass a zone command --zone with the zone's ID"
	for _, tt := range []struct {
		name  string
		setup func(h *harness)
		want  []string
		// parentLookup is false when the zone example.com must not be
		// looked up.
		parentLookup bool
	}{
		{"403", func(h *harness) { forbidZoneLookups(h, nil) }, []string{"Zone > Zone > Read", "HTTP 403", skip}, true},
		{"403 not an envelope", func(h *harness) {
			h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
				if r.URL.Path != "/zones" {
					return false
				}
				cftest.WriteRaw(w, http.StatusForbidden, "text/html", "<html>Forbidden</html>")
				return true
			}
		}, []string{"Zone > Zone > Read", "HTTP 403", skip}, true},
		{"no match", func(h *harness) { h.env["AOP_HOSTNAMES"] = "app.example.org" }, []string{
			"no active zone matches hostname app.example.org: check that CLOUDFLARE_API_TOKEN can read the zone, which needs Zone > Zone > Read",
		}, true},
		{"ambiguous", func(h *harness) {
			h.fake.Zones = append(h.fake.Zones, cftest.ZoneEntry{ID: "0123456789abcdef0123456789abcdef", Name: "example.com", Status: cftest.StatusActive})
		}, []string{"hostname a.example.com matches 2 active zones named example.com: set CLOUDFLARE_ZONE_ID to the zone's ID"}, true},
		// A failed lookup of the subdomain zone must not let its parent
		// zone match.
		{"subdomain zone lookup fails", func(h *harness) {
			h.env["AOP_HOSTNAMES"] = euA
			h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
				if r.URL.Path != "/zones" || r.URL.Query().Get("name") != "eu.example.com" {
					return false
				}
				cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
				return true
			}
		}, []string{"find the zone of a.eu.example.com: list zones named eu.example.com: GET /zones: HTTP 500"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := lookupHarness(t)
			h.env["AOP_HOSTNAMES"] = hostA
			tt.setup(h)
			code, _, stderr := h.run("hostname", "issue")
			assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
			for _, want := range tt.want {
				assert.Contains(t, stderr, want)
			}
			assert.Empty(t, aopRequests(h), "AOP requests sent")
			if !tt.parentLookup {
				for _, r := range zoneRequests(h) {
					assert.NotContains(t, r.Query, "name=example.com&", "looked up the parent zone after a failed lookup")
				}
			}
		})
	}

	t.Run("cancelled", func(t *testing.T) {
		h, _ := lookupHarness(t)
		h.env["AOP_HOSTNAMES"] = hostA
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		code, _, stderr := h.runContext(ctx, "hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "context canceled")
		assert.Empty(t, aopRequests(h), "AOP requests sent")
	})

	t.Run("status without hostnames", func(t *testing.T) {
		h, _ := lookupHarness(t)
		code, _, stderr := h.run("hostname", "status")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, "aopctl: no zone: pass --zone, set CLOUDFLARE_ZONE_ID or list hostnames\n", stderr, "stderr")
		assert.Empty(t, h.fake.Recorded(), "requests sent")
	})
}

// TestZoneEarlyHints checks the commands that usage errors print before the
// zone is known, which must not point at another zone.
func TestZoneEarlyHints(t *testing.T) {
	for _, tt := range []struct {
		name    string
		noEnv   bool
		args    []string
		command string
	}{
		{"zone prune with another zone", false, []string{"zone", "prune", "--zone", euZone}, "aopctl zone status --zone " + euZone + " to find"},
		{"zone prune", false, []string{"zone", "prune"}, "aopctl zone status" + zoneOpt + " to find"},
		{"hostname prune with a zone name", false, []string{"hostname", "prune", "--zone", "EU.example.com"}, "aopctl hostname status --zone eu.example.com to find"},
		{"hostname prune", false, []string{"hostname", "prune"}, "aopctl hostname status" + zoneOpt + " to find"},
		{"hostname prune without a zone", true, []string{"hostname", "prune"}, "aopctl hostname status to find"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			if tt.noEnv {
				delete(h.env, "CLOUDFLARE_ZONE_ID")
			}
			code, _, stderr := h.run(tt.args...)
			assert.Equal(t, 2, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, "--cert-id is required: run "+tt.command)
			assert.Empty(t, h.fake.Recorded(), "requests sent")
		})
	}
}

func TestZoneFlagInvalid(t *testing.T) {
	for _, args := range [][]string{
		{"hostname", "status", "--zone", "example"},
		{"hostname", "issue", "--zone", "*.example.com"},
		{"zone", "status", "--zone", "example.com:443"},
		{"zone", "prune", "--zone", strings.Repeat("a", 31), "--cert-id", zoneOld},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			h := newHarness(t)
			code, stdout, stderr := h.run(args...)
			assert.Equal(t, 2, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, "aopctl: invalid --zone ")
			assert.Empty(t, stdout, "stdout")
			assert.Empty(t, h.fake.Recorded(), "requests sent")
		})
	}
}
