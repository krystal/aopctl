package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/krystal/aopctl/aopctl"
	"github.com/krystal/aopctl/internal/cftest"
)

var (
	zoneOld = cftest.ZoneCertID(1)
	zoneTwo = cftest.ZoneCertID(2)
	// zoneNew is the ID the fake gives the first zone upload.
	zoneNew = cftest.ZoneCertID(101)
)

// zoneHarness has zone-level AOP enabled and one active zone certificate,
// zoneOld, signed by the CA.
func zoneHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.fake.ZoneEnabled = true
	h.fake.AddZoneCert(zoneOld, h.ca.issue(t), cftest.UploadedOn(1))
	return h
}

// noPrompt fails the test if the command opens the terminal.
func noPrompt(t *testing.T, h *harness) {
	t.Helper()
	h.openTTY = func() (io.ReadWriteCloser, error) {
		t.Error("opened the terminal to confirm")
		return nil, io.EOF
	}
}

func answer(h *harness, input string) *fakeTTY {
	tty := &fakeTTY{Reader: strings.NewReader(input)}
	h.openTTY = func() (io.ReadWriteCloser, error) { return tty, nil }
	return tty
}

func zoneUploads(h *harness) int {
	return h.fake.Count(http.MethodPost, "/origin_tls_client_auth")
}

func settingWrites(h *harness) int {
	return h.fake.Count(http.MethodPut, "/settings")
}

func TestZoneUsageErrors(t *testing.T) {
	for _, id := range []string{"", "old", "settings", "hostnames", "../settings", zoneOld + "/x", strings.ToUpper(zoneOld) + "0"} {
		t.Run("prune cert id "+strconv.Quote(id), func(t *testing.T) {
			h := zoneHarness(t)
			code, stdout, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--cert-id", id, "--yes")
			if code != 2 || !strings.Contains(stderr, "want a zone certificate ID, which is a UUID") {
				t.Errorf("exit %d; stderr:\n%s", code, stderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if n := len(h.fake.Recorded()); n != 0 {
				t.Errorf("sent %d requests, want none", n)
			}
		})
	}
	t.Run("prune without cert id", func(t *testing.T) {
		h := zoneHarness(t)
		code, _, stderr := h.run("zone", "prune")
		if code != 2 || !strings.Contains(stderr, "aopctl zone status") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})
	t.Run("help", func(t *testing.T) {
		h := zoneHarness(t)
		if code, _, stderr := h.run("zone", "-h"); code != 0 || !strings.Contains(stderr, "zone enable") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})
}

func TestZoneIssue(t *testing.T) {
	h := zoneHarness(t)
	noPrompt(t, h)
	code, stdout, stderr := h.run("zone", "issue")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	reqs := h.fake.Recorded()

	var upload struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	for _, r := range reqs {
		if r.Method == http.MethodPost {
			if !strings.HasSuffix(r.Path, "/zones/"+cftest.Zone+"/origin_tls_client_auth") {
				t.Errorf("uploaded to %s", r.Path)
			}
			if err := json.Unmarshal(r.Body, &upload); err != nil {
				t.Fatalf("upload body: %v", err)
			}
		}
	}
	leaf, err := aopctl.ParseCertificatePEM(upload.Certificate)
	if err != nil {
		t.Fatalf("uploaded certificate: %v", err)
	}
	if err := cftest.VerifyClientAuth(leaf, h.ca.cert, leaf.NotBefore.Add(2*time.Hour)); err != nil {
		t.Errorf("uploaded leaf does not verify for client auth: %v", err)
	}
	key, err := aopctl.ParsePrivateKeyPEM(upload.PrivateKey)
	if err != nil || !cftest.KeyMatches(leaf, key) {
		t.Errorf("uploaded key does not match the leaf: %v", err)
	}
	if strings.Contains(stdout+stderr, strings.Split(upload.PrivateKey, "\n")[1]) {
		t.Error("output contains the leaf key")
	}
	if n := countIn(reqs, http.MethodGet, "/origin_tls_client_auth/"+zoneNew); n < 2 {
		t.Errorf("polled the new certificate %d times, want it polled to active", n)
	}
	if w := h.fake.Writes(); len(w) != 1 {
		t.Errorf("sent %d writes, want only the upload: %+v", len(w), w)
	}
	for _, want := range []string{
		"Zone-level AOP: enabled",
		"In use: " + zoneOld + " (derived: the newest active certificate)",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	for _, want := range []string{
		"Certificate " + zoneNew + " is active",
		"Cloudflare no longer uses: " + zoneOld,
		"  aopctl zone prune --cert-id " + zoneOld + "\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
}

// TestZoneIssueConfirmation checks that zone issue asks before a new
// certificate takes over from one AOP_CA_CERT did not sign, and only then.
func TestZoneIssueConfirmation(t *testing.T) {
	// otherInUse has zone-level AOP enabled, with the newest active
	// certificate, zoneTwo, from another CA. zoneOld is the CA's, but older.
	otherInUse := func(t *testing.T) *harness {
		t.Helper()
		h := zoneHarness(t)
		h.fake.AddZoneCert(zoneTwo, newTestCA(t, 3650).issue(t), cftest.UploadedOn(2))
		return h
	}

	t.Run("other CA in use, declined", func(t *testing.T) {
		h := otherInUse(t)
		tty := answer(h, "n\n")
		code, _, stderr := h.run("zone", "issue")
		if !strings.Contains(tty.prompt.String(), "[y/N]") {
			t.Errorf("prompt = %q", tty.prompt.String())
		}
		if code != 1 || !strings.Contains(stderr, "aborted: nothing uploaded") || !strings.Contains(stderr, "Warning: AOP_CA_CERT did not sign the certificate in use") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := zoneUploads(h); n != 0 {
			t.Errorf("sent %d uploads after the prompt was declined", n)
		}
	})

	t.Run("other CA in use, confirmed", func(t *testing.T) {
		h := otherInUse(t)
		answer(h, "y\n")
		code, stdout, stderr := h.run("zone", "issue")
		if code != 0 || zoneUploads(h) != 1 {
			t.Fatalf("exit %d, %d uploads; stderr:\n%s", code, zoneUploads(h), stderr)
		}
		// Both previously active certificates get prune hints, with the
		// other CA's marked.
		for _, want := range []string{
			"  aopctl zone prune --cert-id " + zoneOld + "\n",
			"AOP_CA_CERT did not sign " + zoneTwo,
			"  aopctl zone prune --cert-id " + zoneTwo + "\n",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout lacks %q:\n%s", want, stdout)
			}
		}
	})

	t.Run("other CA in use, no terminal", func(t *testing.T) {
		h := otherInUse(t)
		code, _, stderr := h.run("zone", "issue")
		if code != 1 || !strings.Contains(stderr, "--yes") || zoneUploads(h) != 0 {
			t.Errorf("exit %d, %d uploads; stderr:\n%s", code, zoneUploads(h), stderr)
		}
	})

	t.Run("other CA in use, yes", func(t *testing.T) {
		h := otherInUse(t)
		noPrompt(t, h)
		if code, _, stderr := h.run("zone", "issue", "--yes"); code != 0 || zoneUploads(h) != 1 {
			t.Errorf("exit %d, %d uploads; stderr:\n%s", code, zoneUploads(h), stderr)
		}
	})

	t.Run("other CA in use, dry run", func(t *testing.T) {
		h := otherInUse(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "issue", "--dry-run")
		if code != 0 || !strings.Contains(stderr, "Dry run: nothing changed.") || !strings.Contains(stderr, "In use: "+zoneTwo) {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if w := h.fake.Writes(); len(w) != 0 {
			t.Errorf("dry run sent %d writes", len(w))
		}
	})

	t.Run("other CA active but older", func(t *testing.T) {
		// The CA's certificate is newer but listed second, so the in-use
		// certificate is derived from uploaded_on, not list order.
		h := newHarness(t)
		h.fake.ZoneEnabled = true
		h.fake.AddZoneCert(zoneTwo, newTestCA(t, 3650).issue(t), cftest.UploadedOn(1))
		h.fake.AddZoneCert(zoneOld, h.ca.issue(t), cftest.UploadedOn(2))
		noPrompt(t, h)
		if code, _, stderr := h.run("zone", "issue"); code != 0 || zoneUploads(h) != 1 {
			t.Errorf("exit %d, %d uploads; stderr:\n%s", code, zoneUploads(h), stderr)
		}
	})

	t.Run("in use cannot be derived", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(1))
		tty := answer(h, "n\n")
		code, _, stderr := h.run("zone", "issue")
		if !strings.Contains(tty.prompt.String(), "[y/N]") || code != 1 || zoneUploads(h) != 0 {
			t.Errorf("exit %d, prompt %q; stderr:\n%s", code, tty.prompt.String(), stderr)
		}
		if !strings.Contains(stderr, "In use: unknown") {
			t.Errorf("stderr lacks the unknown in-use certificate:\n%s", stderr)
		}
	})

	t.Run("other CA, setting disabled", func(t *testing.T) {
		h := otherInUse(t)
		h.fake.ZoneEnabled = false
		noPrompt(t, h)
		code, stdout, stderr := h.run("zone", "issue")
		if code != 0 || zoneUploads(h) != 1 {
			t.Fatalf("exit %d, %d uploads; stderr:\n%s", code, zoneUploads(h), stderr)
		}
		if !strings.Contains(stdout, "Zone-level AOP is disabled") || !strings.Contains(stdout, "  aopctl zone enable\n") || strings.Contains(stdout, "zone prune") {
			t.Errorf("stdout:\n%s", stdout)
		}
		if settingWrites(h) != 0 || len(deletes(h)) != 0 {
			t.Errorf("changed the setting or deleted a certificate")
		}
	})

	t.Run("no certificate yet", func(t *testing.T) {
		h := newHarness(t)
		h.fake.ZoneEnabled = true
		noPrompt(t, h)
		code, stdout, stderr := h.run("zone", "issue")
		if code != 0 || !strings.Contains(stdout, "No other zone certificate was active.") {
			t.Errorf("exit %d; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
	})
}

func TestZoneIssueFailures(t *testing.T) {
	t.Run("upload server error", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, body []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			// The certificate is created, but the response is an error.
			h.fake.UploadZone(httptest.NewRecorder(), body)
			cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
			return true
		}
		code, _, stderr := h.run("zone", "issue")
		if code != 1 || !strings.Contains(stderr, "upload outcome unknown") || !strings.Contains(stderr, "run aopctl zone status before retrying") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if zoneUploads(h) != 1 || len(h.fake.Writes()) != 1 {
			t.Errorf("sent %d uploads and %d writes, want one upload only", zoneUploads(h), len(h.fake.Writes()))
		}
	})

	t.Run("upload response with an invalid ID", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			cftest.WriteEnvelope(w, http.StatusOK, map[string]any{"id": "settings"}, nil)
			return true
		}
		code, _, stderr := h.run("zone", "issue")
		if code != 1 || !strings.Contains(stderr, "upload outcome unknown: the response has an invalid certificate ID") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if n := h.fake.Count(http.MethodGet, "/settings"); n != 1 {
			t.Errorf("read the settings path %d times, want only the plan's read", n)
		}
	})

	t.Run("upload rejected", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			cftest.WriteAPIError(w, http.StatusBadRequest, 1400, "missing leaf certificate")
			return true
		}
		code, _, stderr := h.run("zone", "issue")
		if code != 1 || !strings.Contains(stderr, "upload failed") || strings.Contains(stderr, "outcome unknown") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("deployment timed out", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.UploadStatuses = []string{"pending_deployment", cftest.StatusDeploymentTimedOut}
		code, _, stderr := h.run("zone", "issue")
		if code != 1 || !strings.Contains(stderr, "certificate "+zoneNew+" is deployment_timed_out") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		for _, want := range []string{
			"New certificate " + zoneNew + " did not become active.",
			"Cloudflare uses it if it becomes active later",
			"  aopctl zone prune --cert-id " + zoneNew + "\n",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr lacks %q:\n%s", want, stderr)
			}
		}
		if len(deletes(h)) != 0 || settingWrites(h) != 0 {
			t.Error("deleted a certificate or changed the setting")
		}

		prune := commandLines(stderr, "aopctl zone prune --cert-id "+zoneNew)
		if len(prune) != 1 {
			t.Fatalf("want one prune command, got %q", prune)
		}
		if code, _, stderr := h.run(append(prune[0], "--yes")...); code != 0 {
			t.Fatalf("prune: exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); strings.Join(d, ",") != zoneNew {
			t.Errorf("deleted %v, want %s", d, zoneNew)
		}
	})

	t.Run("never active", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.ZoneEnabled = false
		h.fake.UploadStatuses = []string{"pending_deployment"}
		h.waitLimit = 3
		code, _, stderr := h.run("zone", "issue")
		if code != 1 || !strings.Contains(stderr, "timed out waiting for certificate "+zoneNew+" to become active: last status pending_deployment") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if strings.Contains(stderr, "Cloudflare uses it") || !strings.Contains(stderr, "aopctl zone prune --cert-id "+zoneNew) {
			t.Errorf("stderr:\n%s", stderr)
		}
	})

	t.Run("polling recovers from a server error", func(t *testing.T) {
		h := zoneHarness(t)
		failed := false
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if failed || r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/"+zoneNew) {
				return false
			}
			failed = true
			cftest.WriteAPIError(w, http.StatusServiceUnavailable, 1000, "unavailable")
			return true
		}
		if code, _, stderr := h.run("zone", "issue"); code != 0 || !failed {
			t.Errorf("exit %d, failed a poll: %v; stderr:\n%s", code, failed, stderr)
		}
	})
}

func TestZoneEnable(t *testing.T) {
	// disabledHarness has zone-level AOP disabled and zoneOld active.
	disabledHarness := func(t *testing.T) *harness {
		t.Helper()
		h := zoneHarness(t)
		h.fake.ZoneEnabled = false
		return h
	}

	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, h *harness)
		want  string
	}{
		{"no certificate", func(_ *testing.T, h *harness) {
			h.fake.ZoneCerts = nil
		}, "no active zone-level certificate: upload one with aopctl zone issue"},
		{"only a pending certificate", func(t *testing.T, h *harness) {
			h.fake.ZoneCerts = nil
			h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(2), "pending_deployment")
		}, "no active zone-level certificate"},
		{"newest active from another CA", func(t *testing.T, h *harness) {
			h.fake.AddZoneCert(zoneTwo, newTestCA(t, 3650).issue(t), cftest.UploadedOn(2))
		}, "certificate " + zoneTwo + " is not signed by AOP_CA_CERT"},
		{"newest cannot be derived", func(t *testing.T, h *harness) {
			h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), "")
		}, "cannot tell which active zone-level certificate"},
	} {
		t.Run("refuses "+tt.name, func(t *testing.T) {
			h := disabledHarness(t)
			tt.setup(t, h)
			noPrompt(t, h)
			code, _, stderr := h.run("zone", "enable", "--yes")
			if code != 1 || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit %d; stderr:\n%s", code, stderr)
			}
			if w := h.fake.Writes(); len(w) != 0 {
				t.Errorf("sent %d writes", len(w))
			}
		})
	}

	t.Run("already enabled", func(t *testing.T) {
		h := zoneHarness(t)
		// The rules apply only to a change, and nothing changes.
		h.fake.AddZoneCert(zoneTwo, newTestCA(t, 3650).issue(t), cftest.UploadedOn(2))
		noPrompt(t, h)
		code, stdout, stderr := h.run("zone", "enable")
		if code != 0 || !strings.Contains(stdout, "Zone-level AOP is already enabled. Nothing changed.") {
			t.Errorf("exit %d; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if w := h.fake.Writes(); len(w) != 0 {
			t.Errorf("sent %d writes", len(w))
		}
	})

	t.Run("enables", func(t *testing.T) {
		h := disabledHarness(t)
		h.fake.AddZoneCert(zoneTwo, newTestCA(t, 3650).issue(t), cftest.UploadedOn(0))
		tty := answer(h, "y\n")
		code, stdout, stderr := h.run("zone", "enable")
		if code != 0 || !h.fake.ZoneEnabled {
			t.Fatalf("exit %d, enabled %v; stderr:\n%s", code, h.fake.ZoneEnabled, stderr)
		}
		if !strings.Contains(tty.prompt.String(), "Enable zone-level AOP? [y/N]") {
			t.Errorf("prompt = %q", tty.prompt.String())
		}
		writes := h.fake.Writes()
		if len(writes) != 1 || writes[0].Method != http.MethodPut || !strings.HasSuffix(writes[0].Path, "/origin_tls_client_auth/settings") || string(writes[0].Body) != `{"enabled":true}` {
			t.Fatalf("writes = %+v, want one PUT of {\"enabled\":true} to the settings", writes)
		}
		if n := countIn(requestsAfter(h.fake.Recorded(), http.MethodPut, "/settings"), http.MethodGet, "/settings"); n != 1 {
			t.Errorf("read the setting back %d times, want 1", n)
		}
		if n := h.fake.Count(http.MethodGet, "/zones/"+cftest.Zone+"/settings/tls_client_auth"); n != 0 {
			t.Errorf("read the global AOP setting %d times", n)
		}
		for _, want := range []string{
			"Cloudflare presents certificate " + zoneOld,
			"PUT /zones/{zone}/origin_tls_client_auth/settings\n  {\"enabled\":false}",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout lacks %q:\n%s", want, stdout)
			}
		}
	})

	t.Run("declined", func(t *testing.T) {
		h := disabledHarness(t)
		answer(h, "n\n")
		if code, _, stderr := h.run("zone", "enable"); code != 1 || settingWrites(h) != 0 || h.fake.ZoneEnabled {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("no terminal", func(t *testing.T) {
		h := disabledHarness(t)
		if code, _, stderr := h.run("zone", "enable"); code != 1 || !strings.Contains(stderr, "--yes") || settingWrites(h) != 0 {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("dry run", func(t *testing.T) {
		h := disabledHarness(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "enable", "--dry-run")
		if code != 0 || !strings.Contains(stderr, "Dry run: nothing changed.") || len(h.fake.Writes()) != 0 {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("newest changes before the change", func(t *testing.T) {
		h := disabledHarness(t)
		other := newTestCA(t, 3650).issue(t)
		lists := 0
		h.fake.Hook = func(_ http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/origin_tls_client_auth") {
				lists++
				if lists == 2 {
					h.fake.ZoneCerts = append(h.fake.ZoneCerts, &cftest.Cert{ID: zoneTwo, PEM: other, Statuses: []string{cftest.StatusActive}, UploadedOn: cftest.UploadedOn(2)})
				}
			}
			return false
		}
		code, _, stderr := h.run("zone", "enable", "--yes")
		if code != 1 || !strings.Contains(stderr, "certificate "+zoneTwo+" is not signed by AOP_CA_CERT") || settingWrites(h) != 0 {
			t.Errorf("exit %d, %d setting writes; stderr:\n%s", code, settingWrites(h), stderr)
		}
	})

	for _, tt := range []struct {
		name    string
		respond func(t *testing.T, w http.ResponseWriter)
		unknown bool
	}{
		{"server error", func(_ *testing.T, w http.ResponseWriter) {
			cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
		}, true},
		{"reset connection", func(t *testing.T, w http.ResponseWriter) { cftest.ResetConnection(t, w) }, true},
		{"rejected", func(_ *testing.T, w http.ResponseWriter) {
			cftest.WriteAPIError(w, http.StatusBadRequest, 1400, "invalid request")
		}, false},
	} {
		t.Run("PUT "+tt.name, func(t *testing.T) {
			h := disabledHarness(t)
			h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
				if r.Method != http.MethodPut {
					return false
				}
				tt.respond(t, w)
				return true
			}
			code, _, stderr := h.run("zone", "enable", "--yes")
			unknown := strings.Contains(stderr, "zone-level AOP may now be enabled") && strings.Contains(stderr, "check it with aopctl zone status before retrying")
			if code != 1 || unknown != tt.unknown || !strings.Contains(stderr, "enable zone-level AOP: PUT") {
				t.Errorf("exit %d, reported an unknown outcome: %v, want %v; stderr:\n%s", code, unknown, tt.unknown, stderr)
			}
		})
	}

	t.Run("read back fails", func(t *testing.T) {
		h := disabledHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/settings") || !h.fake.ZoneEnabled {
				return false
			}
			cftest.WriteAPIError(w, http.StatusBadGateway, 1000, "bad gateway")
			return true
		}
		code, _, stderr := h.run("zone", "enable", "--yes")
		if code != 1 || !strings.Contains(stderr, "zone-level AOP may now be enabled: read zone-level AOP setting back") || !strings.Contains(stderr, "aopctl zone status") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("setting reads back disabled", func(t *testing.T) {
		h := disabledHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPut {
				return false
			}
			cftest.WriteEnvelope(w, http.StatusOK, map[string]any{"enabled": true}, nil)
			return true
		}
		code, _, stderr := h.run("zone", "enable", "--yes")
		if code != 1 || !strings.Contains(stderr, "zone-level AOP still reads as disabled") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})
}

func TestZoneStatus(t *testing.T) {
	h := zoneHarness(t)
	h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(2))
	h.fake.AddZoneCert(cftest.ZoneCertID(3), newTestCA(t, 3650).issue(t), cftest.UploadedOn(3), "pending_deployment")
	code, stdout, stderr := h.run("zone", "status")
	if code != 0 {
		t.Fatalf("exit %d; stderr:\n%s", code, stderr)
	}
	if w := h.fake.Writes(); len(w) != 0 {
		t.Errorf("sent %d writes", len(w))
	}
	for _, want := range []string{
		"Zone-level AOP: enabled\n",
		"Certificates (3):\n",
		"  " + zoneOld + "\n    status:    active\n    subject:   existing leaf\n    key type:  ECDSA P-256\n    fingerprint: ",
		"  " + zoneTwo + "  [in use, derived from uploaded_on]\n",
		"    uploaded:  " + cftest.UploadedOn(2) + "\n",
		"    enabled:   true (Cloudflare's per-certificate field, undocumented)\n",
		"    signed by AOP_CA_CERT: yes\n",
		"    status:    pending_deployment\n",
		"    signed by AOP_CA_CERT: no\n",
		"In use: " + zoneTwo + " (derived: the newest active certificate)\n",
		"Warning: 2 certificates are active.",
		"Per-hostname certificates override zone-level ones",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if n := strings.Count(stdout, "[in use"); n != 1 {
		t.Errorf("marked %d certificates as in use, want 1", n)
	}

	t.Run("disabled, without AOP_CA_CERT", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.ZoneEnabled = false
		delete(h.env, "AOP_CA_CERT")
		code, stdout, stderr := h.run("zone", "status")
		if code != 0 {
			t.Fatalf("exit %d; stderr:\n%s", code, stderr)
		}
		for _, want := range []string{
			"Zone-level AOP: disabled",
			"signed by AOP_CA_CERT: unknown (AOP_CA_CERT not set)",
			"In use: none, zone-level AOP is disabled",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout lacks %q:\n%s", want, stdout)
			}
		}
		if strings.Contains(stdout, "[in use") || strings.Contains(stdout, "Warning") {
			t.Errorf("stdout:\n%s", stdout)
		}
	})

	t.Run("listed ID that is not a UUID", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.AddZoneCert("settings", h.ca.issue(t), cftest.UploadedOn(2))
		code, _, stderr := h.run("zone", "status")
		if code != 1 || !strings.Contains(stderr, "the list has an invalid certificate ID") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("pages", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.PerPage = 1
		h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(2))
		code, stdout, stderr := h.run("zone", "status")
		if code != 0 || !strings.Contains(stdout, "Certificates (2):") || !strings.Contains(stdout, "  "+zoneTwo+"  [in use") {
			t.Errorf("exit %d; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
	})

	t.Run("a page repeated", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(2))
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/origin_tls_client_auth") {
				return false
			}
			// Paging ignored: every page is the whole list.
			cftest.WriteEnvelope(w, http.StatusOK, []any{
				map[string]any{"id": zoneOld, "status": "active"},
				map[string]any{"id": zoneTwo, "status": "active"},
			}, map[string]any{"result_info": map[string]any{"page": 1, "total_pages": 2}})
			return true
		}
		code, _, stderr := h.run("zone", "status")
		if code != 1 || !strings.Contains(stderr, "more than once") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})
}

func TestZonePrune(t *testing.T) {
	// twoActive has zoneOld and the newer zoneTwo active and signed by the
	// CA, with zone-level AOP enabled.
	twoActive := func(t *testing.T) *harness {
		t.Helper()
		h := zoneHarness(t)
		h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(2))
		return h
	}

	t.Run("deletes", func(t *testing.T) {
		h := twoActive(t)
		tty := answer(h, "y\n")
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld)
		if code != 0 || strings.Join(deletes(h), ",") != zoneOld || !strings.Contains(stderr, "Deleted "+zoneOld) {
			t.Errorf("exit %d, deleted %v; stderr:\n%s", code, deletes(h), stderr)
		}
		if !strings.Contains(tty.prompt.String(), "Delete 1 zone certificate(s)? [y/N]") {
			t.Errorf("prompt = %q", tty.prompt.String())
		}
		if n := h.fake.Count(http.MethodGet, "/origin_tls_client_auth/"+zoneOld); n < 3 {
			t.Errorf("polled %d times, want polling until gone", n)
		}
	})

	t.Run("declined", func(t *testing.T) {
		h := twoActive(t)
		answer(h, "n\n")
		if code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld); code != 1 || len(deletes(h)) != 0 {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("dry run", func(t *testing.T) {
		h := twoActive(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--dry-run")
		if code != 0 || !strings.Contains(stderr, "Certificates to delete:\n  "+zoneOld) || !strings.Contains(stderr, "Dry run: nothing changed.") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if w := h.fake.Writes(); len(w) != 0 {
			t.Errorf("dry run sent %d writes", len(w))
		}
	})

	// otherFallback has zone-level AOP enabled, with zoneOld, the CA's, in
	// use and an older active certificate, zoneTwo, from another CA.
	otherFallback := func(t *testing.T) *harness {
		t.Helper()
		h := newHarness(t)
		h.fake.ZoneEnabled = true
		h.fake.AddZoneCert(zoneTwo, newTestCA(t, 3650).issue(t), cftest.UploadedOn(1))
		h.fake.AddZoneCert(zoneOld, h.ca.issue(t), cftest.UploadedOn(2))
		return h
	}
	fallbackWarning := "Warning: after the deletes, Cloudflare uses certificate " + zoneTwo + " for every origin without a per-hostname certificate. AOP_CA_CERT did not sign it"

	t.Run("falls back to another CA, declined", func(t *testing.T) {
		h := otherFallback(t)
		tty := answer(h, "n\n")
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld)
		if !strings.Contains(tty.prompt.String(), "[y/N]") {
			t.Errorf("prompt = %q", tty.prompt.String())
		}
		for _, want := range []string{
			fallbackWarning,
			"After the deletes, Cloudflare uses: " + zoneTwo + " (derived: the newest remaining active certificate), signed by AOP_CA_CERT: no",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr lacks %q:\n%s", want, stderr)
			}
		}
		if code != 1 || len(deletes(h)) != 0 {
			t.Errorf("exit %d, deleted %v", code, deletes(h))
		}
	})

	t.Run("falls back to another CA, yes", func(t *testing.T) {
		h := otherFallback(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--yes")
		if code != 0 || strings.Join(deletes(h), ",") != zoneOld || !strings.Contains(stderr, fallbackWarning) {
			t.Errorf("exit %d, deleted %v; stderr:\n%s", code, deletes(h), stderr)
		}
	})

	t.Run("falls back to the CA's own certificate", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(2))
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneTwo, "--yes")
		if code != 0 || strings.Contains(stderr, "Warning") || !strings.Contains(stderr, "After the deletes, Cloudflare uses: "+zoneOld) {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("other CA left in place while disabled", func(t *testing.T) {
		h := otherFallback(t)
		h.fake.ZoneEnabled = false
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--yes")
		if code != 0 || strings.Contains(stderr, "Warning") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
	})

	t.Run("last active while enabled", func(t *testing.T) {
		h := zoneHarness(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--yes")
		if code != 1 || !strings.Contains(stderr, "Refused "+zoneOld+": it is the last active zone certificate") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); len(d) != 0 {
			t.Errorf("deleted %v", d)
		}
	})

	t.Run("last active while disabled", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.ZoneEnabled = false
		if code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--yes"); code != 0 || strings.Join(deletes(h), ",") != zoneOld {
			t.Errorf("exit %d, deleted %v; stderr:\n%s", code, deletes(h), stderr)
		}
	})

	t.Run("every active one keeps the newest", func(t *testing.T) {
		h := twoActive(t)
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneTwo, "--cert-id", zoneOld, "--yes")
		if code != 1 || !strings.Contains(stderr, "Refused "+zoneTwo+": it is the last active zone certificate") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); strings.Join(d, ",") != zoneOld {
			t.Errorf("deleted %v, want %s only", d, zoneOld)
		}
	})

	t.Run("re-check before the delete", func(t *testing.T) {
		// The plan sees two active certificates. Before the delete, the other
		// one is being deleted, so zoneOld is the last active one.
		h := twoActive(t)
		lists := 0
		h.fake.Hook = func(_ http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/origin_tls_client_auth") {
				lists++
				if lists == 2 {
					h.fake.ZoneCerts[1].Statuses = []string{cftest.StatusPendingDeletion}
				}
			}
			return false
		}
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--yes")
		if lists < 2 {
			t.Fatalf("listed %d times, want a re-check before the delete", lists)
		}
		if code != 1 || !strings.Contains(stderr, "Refused "+zoneOld+": it is now the last active zone certificate") {
			t.Errorf("exit %d; stderr:\n%s", code, stderr)
		}
		if d := deletes(h); len(d) != 0 {
			t.Errorf("deleted %v", d)
		}
	})

	t.Run("re-check sees the setting enabled", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.ZoneEnabled = false
		reads := 0
		h.fake.Hook = func(_ http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/settings") {
				reads++
				if reads == 2 {
					h.fake.ZoneEnabled = true
				}
			}
			return false
		}
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--yes")
		if code != 1 || len(deletes(h)) != 0 || !strings.Contains(stderr, "now the last active") {
			t.Errorf("exit %d, deleted %v; stderr:\n%s", code, deletes(h), stderr)
		}
	})

	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, h *harness) string
		want  string
		code  int
	}{
		{"not found", func(*testing.T, *harness) string { return cftest.ZoneCertID(9) }, "Refused " + cftest.ZoneCertID(9) + ": not found", 1},
		{"other CA", func(t *testing.T, h *harness) string {
			h.fake.AddZoneCert(zoneTwo, newTestCA(t, 3650).issue(t), cftest.UploadedOn(0))
			return zoneTwo
		}, "Refused " + zoneTwo + ": certificate " + zoneTwo + " is not signed by AOP_CA_CERT", 1},
		{"already deleted", func(t *testing.T, h *harness) string {
			h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(0), cftest.StatusDeleted)
			return zoneTwo
		}, "Already deleted: " + zoneTwo, 0},
	} {
		t.Run("refuses "+tt.name, func(t *testing.T) {
			h := zoneHarness(t)
			id := tt.setup(t, h)
			code, _, stderr := h.run("zone", "prune", "--cert-id", id, "--yes")
			if code != tt.code || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit %d, want %d; stderr:\n%s", code, tt.code, stderr)
			}
			if d := deletes(h); len(d) != 0 {
				t.Errorf("deleted %v", d)
			}
		})
	}

	t.Run("pending deletion is waited for", func(t *testing.T) {
		h := twoActive(t)
		h.fake.AddZoneCert(cftest.ZoneCertID(3), h.ca.issue(t), cftest.UploadedOn(0), cftest.StatusPendingDeletion, "gone")
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "prune", "--cert-id", cftest.ZoneCertID(3))
		if code != 0 || len(deletes(h)) != 0 || !strings.Contains(stderr, "Deleted "+cftest.ZoneCertID(3)) {
			t.Errorf("exit %d, deleted %v; stderr:\n%s", code, deletes(h), stderr)
		}
	})
}
