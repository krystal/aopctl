package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		assert.Fail(t, "opened the terminal to confirm")
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
	for _, id := range []string{"", "old", "settings", "hostnames", "../settings", zoneOld + "/x", strings.ToUpper(zoneOld) + "0", strings.Repeat("g", 32), strings.Repeat("a", 31)} {
		t.Run("prune cert id "+strconv.Quote(id), func(t *testing.T) {
			h := zoneHarness(t)
			code, stdout, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--cert-id", id, "--yes")
			assert.Equal(t, 2, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, "want a zone certificate ID, a UUID or 32 hex digits")
			assert.Empty(t, stdout, "stdout")
			assert.Empty(t, h.fake.Recorded(), "requests sent")
		})
	}
	t.Run("prune without cert id", func(t *testing.T) {
		h := zoneHarness(t)
		code, _, stderr := h.run("zone", "prune")
		assert.Equal(t, 2, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "aopctl zone status")
	})
	t.Run("help", func(t *testing.T) {
		h := zoneHarness(t)
		code, stdout, stderr := h.run("zone", "-h")
		assert.Equal(t, 0, code, "exit code; stdout:\n%s\nstderr:\n%s", stdout, stderr)
		assert.Contains(t, stdout, "Turn on zone-level AOP")
	})
}

func TestZoneIssue(t *testing.T) {
	h := zoneHarness(t)
	noPrompt(t, h)
	code, stdout, stderr := h.run("zone", "issue")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	reqs := h.fake.Recorded()

	var upload struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	for _, r := range reqs {
		if r.Method == http.MethodPost {
			assert.True(t, strings.HasSuffix(r.Path, "/zones/"+cftest.Zone+"/origin_tls_client_auth"), "uploaded to %s", r.Path)
			require.NoError(t, json.Unmarshal(r.Body, &upload), "upload body")
		}
	}
	leaf, err := aopctl.ParseCertificatePEM(upload.Certificate)
	require.NoError(t, err, "uploaded certificate")
	assert.NoError(t, cftest.VerifyClientAuth(leaf, h.ca.cert, leaf.NotBefore.Add(2*time.Hour)), "uploaded leaf does not verify for client auth")
	key, err := aopctl.ParsePrivateKeyPEM(upload.PrivateKey)
	if assert.NoError(t, err, "uploaded key") {
		assert.True(t, cftest.KeyMatches(leaf, key), "uploaded key does not match the leaf")
	}
	assert.NotContains(t, stdout+stderr, strings.Split(upload.PrivateKey, "\n")[1], "output contains the leaf key")
	assert.GreaterOrEqual(t, countIn(reqs, http.MethodGet, "/origin_tls_client_auth/"+zoneNew), 2, "polls of the new certificate, want it polled to active")
	assert.Len(t, h.fake.Writes(), 1, "writes, want only the upload")
	for _, want := range []string{
		"Zone-level AOP: enabled",
		"In use: " + zoneOld + " (derived: the newest active certificate)",
	} {
		assert.Contains(t, stderr, want)
	}
	for _, want := range []string{
		"Certificate " + zoneNew + " is active",
		"Cloudflare no longer uses: " + zoneOld,
		"  aopctl zone prune" + zoneOpt + " --cert-id " + zoneOld + "\n",
	} {
		assert.Contains(t, stdout, want)
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
		assert.Contains(t, tty.prompt.String(), "[y/N]", "prompt")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "aborted: nothing uploaded")
		assert.Contains(t, stderr, "Warning: AOP_CA_CERT did not sign the certificate in use")
		assert.Zero(t, zoneUploads(h), "uploads after the prompt was declined")
	})

	t.Run("other CA in use, confirmed", func(t *testing.T) {
		h := otherInUse(t)
		answer(h, "y\n")
		code, stdout, stderr := h.run("zone", "issue")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		require.Equal(t, 1, zoneUploads(h), "uploads")
		// Both previously active certificates get prune hints, with the
		// other CA's marked.
		for _, want := range []string{
			"  aopctl zone prune" + zoneOpt + " --cert-id " + zoneOld + "\n",
			"AOP_CA_CERT did not sign " + zoneTwo,
			"  aopctl zone prune" + zoneOpt + " --cert-id " + zoneTwo + "\n",
		} {
			assert.Contains(t, stdout, want)
		}
	})

	t.Run("other CA in use, no terminal", func(t *testing.T) {
		h := otherInUse(t)
		code, _, stderr := h.run("zone", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "--yes")
		assert.Zero(t, zoneUploads(h), "uploads")
	})

	t.Run("other CA in use, yes", func(t *testing.T) {
		h := otherInUse(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "issue", "--yes")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, 1, zoneUploads(h), "uploads")
	})

	t.Run("other CA in use, dry run", func(t *testing.T) {
		h := otherInUse(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "issue", "--dry-run")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Dry run: nothing changed.")
		assert.Contains(t, stderr, "In use: "+zoneTwo)
		assert.Empty(t, h.fake.Writes(), "dry run writes")
	})

	t.Run("other CA active but older", func(t *testing.T) {
		// The CA's certificate is newer but listed second, so the in-use
		// certificate is derived from uploaded_on, not list order.
		h := newHarness(t)
		h.fake.ZoneEnabled = true
		h.fake.AddZoneCert(zoneTwo, newTestCA(t, 3650).issue(t), cftest.UploadedOn(1))
		h.fake.AddZoneCert(zoneOld, h.ca.issue(t), cftest.UploadedOn(2))
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "issue")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, 1, zoneUploads(h), "uploads")
	})

	t.Run("in use cannot be derived", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(1))
		tty := answer(h, "n\n")
		code, _, stderr := h.run("zone", "issue")
		assert.Contains(t, tty.prompt.String(), "[y/N]", "prompt")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Zero(t, zoneUploads(h), "uploads")
		assert.Contains(t, stderr, "In use: unknown", "stderr lacks the unknown in-use certificate")
	})

	t.Run("other CA, setting disabled", func(t *testing.T) {
		h := otherInUse(t)
		h.fake.ZoneEnabled = false
		noPrompt(t, h)
		code, stdout, stderr := h.run("zone", "issue")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		require.Equal(t, 1, zoneUploads(h), "uploads")
		assert.Contains(t, stdout, "Zone-level AOP is disabled")
		assert.Contains(t, stdout, "  aopctl zone enable"+zoneOpt+"\n")
		assert.NotContains(t, stdout, "zone prune")
		assert.Zero(t, settingWrites(h), "setting writes")
		assert.Empty(t, deletes(h), "deleted")
	})

	t.Run("no certificate yet", func(t *testing.T) {
		h := newHarness(t)
		h.fake.ZoneEnabled = true
		noPrompt(t, h)
		code, stdout, stderr := h.run("zone", "issue")
		assert.Equal(t, 0, code, "exit code; stdout:\n%s\nstderr:\n%s", stdout, stderr)
		assert.Contains(t, stdout, "No other zone certificate was active.")
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
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "upload outcome unknown")
		assert.Contains(t, stderr, "run aopctl zone status"+zoneOpt+" before retrying")
		assert.Equal(t, 1, zoneUploads(h), "uploads")
		assert.Len(t, h.fake.Writes(), 1, "writes, want one upload only")
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
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "upload outcome unknown: the response has an invalid certificate ID")
		assert.Equal(t, 1, h.fake.Count(http.MethodGet, "/settings"), "reads of the settings path, want only the plan's read")
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
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "upload failed")
		assert.NotContains(t, stderr, "outcome unknown")
	})

	t.Run("deployment timed out", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.UploadStatuses = []string{"pending_deployment", cftest.StatusDeploymentTimedOut}
		code, _, stderr := h.run("zone", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "certificate "+zoneNew+" is deployment_timed_out")
		for _, want := range []string{
			"New certificate " + zoneNew + " did not become active.",
			"Cloudflare uses it if it becomes active later",
			"  aopctl zone prune" + zoneOpt + " --cert-id " + zoneNew + "\n",
		} {
			assert.Contains(t, stderr, want)
		}
		assert.Empty(t, deletes(h), "deleted")
		assert.Zero(t, settingWrites(h), "setting writes")

		prune := commandLines(stderr, "aopctl zone prune"+zoneOpt+" --cert-id "+zoneNew)
		require.Len(t, prune, 1, "prune commands")
		code, _, stderr = h.run(append(prune[0], "--yes")...)
		require.Equal(t, 0, code, "prune: exit code; stderr:\n%s", stderr)
		assert.Equal(t, zoneNew, strings.Join(deletes(h), ","), "deleted")
	})

	t.Run("never active", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.ZoneEnabled = false
		h.fake.UploadStatuses = []string{"pending_deployment"}
		h.waitLimit = 3
		code, _, stderr := h.run("zone", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "timed out waiting for certificate "+zoneNew+" to become active: last status pending_deployment")
		assert.NotContains(t, stderr, "Cloudflare uses it")
		assert.Contains(t, stderr, "aopctl zone prune"+zoneOpt+" --cert-id "+zoneNew)
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
		code, _, stderr := h.run("zone", "issue")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.True(t, failed, "failed a poll")
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
		}, "no active zone-level certificate: upload one with aopctl zone issue" + zoneOpt},
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
			assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, tt.want)
			assert.Empty(t, h.fake.Writes(), "writes")
		})
	}

	t.Run("already enabled", func(t *testing.T) {
		h := zoneHarness(t)
		// The rules apply only to a change, and nothing changes.
		h.fake.AddZoneCert(zoneTwo, newTestCA(t, 3650).issue(t), cftest.UploadedOn(2))
		noPrompt(t, h)
		code, stdout, stderr := h.run("zone", "enable")
		assert.Equal(t, 0, code, "exit code; stdout:\n%s\nstderr:\n%s", stdout, stderr)
		assert.Contains(t, stdout, "Zone-level AOP is already enabled. Nothing changed.")
		assert.Empty(t, h.fake.Writes(), "writes")
	})

	t.Run("enables", func(t *testing.T) {
		h := disabledHarness(t)
		h.fake.AddZoneCert(zoneTwo, newTestCA(t, 3650).issue(t), cftest.UploadedOn(0))
		tty := answer(h, "y\n")
		code, stdout, stderr := h.run("zone", "enable")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		require.True(t, h.fake.ZoneEnabled, "enabled")
		assert.Contains(t, tty.prompt.String(), "Enable zone-level AOP? [y/N]", "prompt")
		writes := h.fake.Writes()
		require.Len(t, writes, 1, "writes, want one PUT of {\"enabled\":true} to the settings")
		require.Equal(t, http.MethodPut, writes[0].Method, "write method")
		require.True(t, strings.HasSuffix(writes[0].Path, "/origin_tls_client_auth/settings"), "write path %s", writes[0].Path)
		require.Equal(t, `{"enabled":true}`, string(writes[0].Body), "write body")
		assert.Equal(t, 1, countIn(requestsAfter(h.fake.Recorded(), http.MethodPut, "/settings"), http.MethodGet, "/settings"), "reads of the setting back")
		assert.Zero(t, h.fake.Count(http.MethodGet, "/zones/"+cftest.Zone+"/settings/tls_client_auth"), "reads of the global AOP setting")
		for _, want := range []string{
			"Cloudflare presents certificate " + zoneOld,
			"PUT /zones/{zone}/origin_tls_client_auth/settings\n  {\"enabled\":false}",
		} {
			assert.Contains(t, stdout, want)
		}
	})

	t.Run("declined", func(t *testing.T) {
		h := disabledHarness(t)
		answer(h, "n\n")
		code, _, stderr := h.run("zone", "enable")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Zero(t, settingWrites(h), "setting writes")
		assert.False(t, h.fake.ZoneEnabled, "enabled")
	})

	t.Run("no terminal", func(t *testing.T) {
		h := disabledHarness(t)
		code, _, stderr := h.run("zone", "enable")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "--yes")
		assert.Zero(t, settingWrites(h), "setting writes")
	})

	t.Run("dry run", func(t *testing.T) {
		h := disabledHarness(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "enable", "--dry-run")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Dry run: nothing changed.")
		assert.Empty(t, h.fake.Writes(), "writes")
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
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "certificate "+zoneTwo+" is not signed by AOP_CA_CERT")
		assert.Zero(t, settingWrites(h), "setting writes")
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
			unknown := strings.Contains(stderr, "zone-level AOP may now be enabled") && strings.Contains(stderr, "check it with aopctl zone status"+zoneOpt+" before retrying")
			assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
			assert.Equal(t, tt.unknown, unknown, "reported an unknown outcome; stderr:\n%s", stderr)
			assert.Contains(t, stderr, "enable zone-level AOP: PUT")
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
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "zone-level AOP may now be enabled: read zone-level AOP setting back")
		assert.Contains(t, stderr, "aopctl zone status")
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
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "zone-level AOP still reads as disabled")
	})
}

func TestZoneStatus(t *testing.T) {
	h := zoneHarness(t)
	h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(2))
	h.fake.AddZoneCert(cftest.ZoneCertID(3), newTestCA(t, 3650).issue(t), cftest.UploadedOn(3), "pending_deployment")
	code, stdout, stderr := h.run("zone", "status")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	assert.Empty(t, h.fake.Writes(), "writes")
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
		assert.Contains(t, stdout, want)
	}
	assert.Equal(t, 1, strings.Count(stdout, "[in use"), "certificates marked as in use")

	t.Run("disabled, without AOP_CA_CERT", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.ZoneEnabled = false
		delete(h.env, "AOP_CA_CERT")
		code, stdout, stderr := h.run("zone", "status")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		for _, want := range []string{
			"Zone-level AOP: disabled",
			"signed by AOP_CA_CERT: unknown (AOP_CA_CERT not set)",
			"In use: none, zone-level AOP is disabled",
		} {
			assert.Contains(t, stdout, want)
		}
		assert.NotContains(t, stdout, "[in use")
		assert.NotContains(t, stdout, "Warning")
	})

	t.Run("listed ID that is not a UUID", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.AddZoneCert("settings", h.ca.issue(t), cftest.UploadedOn(2))
		code, _, stderr := h.run("zone", "status")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "the list has an invalid certificate ID")
	})

	t.Run("pages", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.PerPage = 1
		h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(2))
		code, stdout, stderr := h.run("zone", "status")
		assert.Equal(t, 0, code, "exit code; stdout:\n%s\nstderr:\n%s", stdout, stderr)
		assert.Contains(t, stdout, "Certificates (2):")
		assert.Contains(t, stdout, "  "+zoneTwo+"  [in use")
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
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "more than once")
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
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, zoneOld, strings.Join(deletes(h), ","), "deleted")
		assert.Contains(t, stderr, "Deleted "+zoneOld)
		assert.Contains(t, tty.prompt.String(), "Delete 1 zone certificate(s)? [y/N]", "prompt")
		assert.GreaterOrEqual(t, h.fake.Count(http.MethodGet, "/origin_tls_client_auth/"+zoneOld), 3, "polls, want polling until gone")
	})

	t.Run("declined", func(t *testing.T) {
		h := twoActive(t)
		answer(h, "n\n")
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld)
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Empty(t, deletes(h), "deleted")
	})

	t.Run("dry run", func(t *testing.T) {
		h := twoActive(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--dry-run")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Certificates to delete:\n  "+zoneOld)
		assert.Contains(t, stderr, "Dry run: nothing changed.")
		assert.Empty(t, h.fake.Writes(), "dry run writes")
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
		assert.Contains(t, tty.prompt.String(), "[y/N]", "prompt")
		for _, want := range []string{
			fallbackWarning,
			"After the deletes, Cloudflare uses: " + zoneTwo + " (derived: the newest remaining active certificate), signed by AOP_CA_CERT: no",
		} {
			assert.Contains(t, stderr, want)
		}
		assert.Equal(t, 1, code, "exit code")
		assert.Empty(t, deletes(h), "deleted")
	})

	t.Run("falls back to another CA, yes", func(t *testing.T) {
		h := otherFallback(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--yes")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, zoneOld, strings.Join(deletes(h), ","), "deleted")
		assert.Contains(t, stderr, fallbackWarning)
	})

	t.Run("falls back to the CA's own certificate", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.AddZoneCert(zoneTwo, h.ca.issue(t), cftest.UploadedOn(2))
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneTwo, "--yes")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.NotContains(t, stderr, "Warning")
		assert.Contains(t, stderr, "After the deletes, Cloudflare uses: "+zoneOld)
	})

	t.Run("other CA left in place while disabled", func(t *testing.T) {
		h := otherFallback(t)
		h.fake.ZoneEnabled = false
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--yes")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.NotContains(t, stderr, "Warning")
	})

	t.Run("last active while enabled", func(t *testing.T) {
		h := zoneHarness(t)
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Refused "+zoneOld+": it is the last active zone certificate")
		assert.Empty(t, deletes(h), "deleted")
	})

	t.Run("last active while disabled", func(t *testing.T) {
		h := zoneHarness(t)
		h.fake.ZoneEnabled = false
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneOld, "--yes")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, zoneOld, strings.Join(deletes(h), ","), "deleted")
	})

	t.Run("every active one keeps the newest", func(t *testing.T) {
		h := twoActive(t)
		code, _, stderr := h.run("zone", "prune", "--cert-id", zoneTwo, "--cert-id", zoneOld, "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Refused "+zoneTwo+": it is the last active zone certificate")
		assert.Equal(t, zoneOld, strings.Join(deletes(h), ","), "deleted, want %s only", zoneOld)
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
		require.GreaterOrEqual(t, lists, 2, "lists, want a re-check before the delete")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Refused "+zoneOld+": it is now the last active zone certificate")
		assert.Empty(t, deletes(h), "deleted")
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
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Empty(t, deletes(h), "deleted")
		assert.Contains(t, stderr, "now the last active")
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
			assert.Equal(t, tt.code, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, tt.want)
			assert.Empty(t, deletes(h), "deleted")
		})
	}

	t.Run("one certificate named in two cases", func(t *testing.T) {
		h := twoActive(t)
		id := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
		h.fake.AddZoneCert(id, h.ca.issue(t), cftest.UploadedOn(0))
		code, _, stderr := h.run("zone", "prune", "--cert-id", strings.ToUpper(id), "--cert-id", id, "--yes")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, id, strings.Join(deletes(h), ","), "deleted")
	})

	t.Run("ID without dashes", func(t *testing.T) {
		h := twoActive(t)
		id := strings.ReplaceAll(cftest.ZoneCertID(3), "-", "")
		h.fake.AddZoneCert(id, h.ca.issue(t), cftest.UploadedOn(0))
		code, stdout, stderr := h.run("zone", "status")
		require.Equal(t, 0, code, "status: exit code; stdout:\n%s\nstderr:\n%s", stdout, stderr)
		require.Contains(t, stdout, "  "+id+"\n", "status")
		code, _, stderr = h.run("zone", "prune", "--cert-id", id, "--yes")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, id, strings.Join(deletes(h), ","), "deleted")
	})

	t.Run("pending deletion is waited for", func(t *testing.T) {
		h := twoActive(t)
		h.fake.AddZoneCert(cftest.ZoneCertID(3), h.ca.issue(t), cftest.UploadedOn(0), cftest.StatusPendingDeletion, "gone")
		noPrompt(t, h)
		code, _, stderr := h.run("zone", "prune", "--cert-id", cftest.ZoneCertID(3))
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Empty(t, deletes(h), "deleted")
		assert.Contains(t, stderr, "Deleted "+cftest.ZoneCertID(3))
	})
}
