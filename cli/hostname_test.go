package cli

import (
	"context"
	"encoding/json"
	"fmt"
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

const (
	hostA = "a.example.com"
	hostB = "b.example.com"
	hostC = "c.example.com"
	hostD = "d.example.com"
)

// issueHarness has hostA and hostB on old-1, hostC on old-2 and hostD with
// no association.
func issueHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.fake.AddCert("old-1", h.ca.issue(t))
	h.fake.AddCert("old-2", h.ca.issue(t))
	h.fake.SetAssoc(hostA, "old-1", new(true))
	h.fake.SetAssoc(hostB, "old-1", new(true))
	h.fake.SetAssoc(hostC, "old-2", new(true))
	h.env["AOP_HOSTNAMES"] = strings.Join([]string{hostA, hostB, hostC, hostD}, ",")
	return h
}

// requestsAfter returns the requests recorded after the first one matching
// method and suffix.
func requestsAfter(reqs []cftest.Request, method, suffix string) []cftest.Request {
	for i, r := range reqs {
		if r.Method == method && strings.HasSuffix(r.Path, suffix) {
			return reqs[i+1:]
		}
	}
	return nil
}

func countIn(reqs []cftest.Request, method, suffix string) int {
	n := 0
	for _, r := range reqs {
		if r.Method == method && strings.HasSuffix(r.Path, suffix) {
			n++
		}
	}
	return n
}

func TestHostnameIssueDryRun(t *testing.T) {
	h := issueHarness(t)
	code, _, stderr := h.run("hostname", "issue", "--dry-run")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	assert.Empty(t, h.fake.Writes(), "dry run write requests")
	for _, want := range []string{
		hostA + ": old-1 (enabled=true) -> new",
		hostC + ": old-2 (enabled=true) -> new",
		hostD + ": none -> new",
		"Dry run: nothing changed.",
	} {
		assert.Contains(t, stderr, want)
	}
}

func TestHostnameIssue(t *testing.T) {
	h := issueHarness(t)
	code, stdout, stderr := h.run("hostname", "issue")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	reqs := h.fake.Recorded()

	var upload struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	for _, r := range reqs {
		if r.Method == http.MethodPost {
			require.NoError(t, json.Unmarshal(r.Body, &upload), "upload body")
		}
	}
	leaf, err := aopctl.ParseCertificatePEM(upload.Certificate)
	require.NoError(t, err, "uploaded certificate")
	assert.NoError(t, cftest.VerifyClientAuth(leaf, h.ca.cert, leaf.NotBefore.Add(2*time.Hour)), "uploaded leaf does not verify for client auth")
	key, err := aopctl.ParsePrivateKeyPEM(upload.PrivateKey)
	require.NoError(t, err, "uploaded key is not PKCS#8")
	assert.True(t, cftest.KeyMatches(leaf, key), "uploaded key does not match the uploaded certificate")
	keyLine := strings.Split(upload.PrivateKey, "\n")[1]
	assert.NotContains(t, stdout+stderr, keyLine, "output contains the leaf key")

	assert.GreaterOrEqual(t, countIn(reqs, http.MethodGet, "/certificates/new-1"), 2, "polls of the new certificate, want it polled to active")

	var put struct {
		Config []struct {
			Hostname string `json:"hostname"`
			CertID   string `json:"cert_id"`
			Enabled  *bool  `json:"enabled"`
		} `json:"config"`
	}
	require.Equal(t, 1, countIn(reqs, http.MethodPut, "/hostnames"), "want exactly one PUT")
	for _, r := range reqs {
		if r.Method == http.MethodPut {
			require.NoError(t, json.Unmarshal(r.Body, &put), "PUT body")
		}
	}
	var putHosts []string
	for _, c := range put.Config {
		putHosts = append(putHosts, c.Hostname)
		assert.Equal(t, "new-1", c.CertID, "PUT entry %+v", c)
		if assert.NotNil(t, c.Enabled, "PUT entry %+v, want enabled", c) {
			assert.True(t, *c.Enabled, "PUT entry %+v, want enabled", c)
		}
	}
	assert.Equal(t, h.env["AOP_HOSTNAMES"], strings.Join(putHosts, ","), "PUT hostnames")
	afterPut := requestsAfter(reqs, http.MethodPut, "/hostnames")
	for _, host := range []string{hostA, hostB, hostC, hostD} {
		assert.GreaterOrEqual(t, countIn(afterPut, http.MethodGet, "/hostnames/"+host), 2, "polls of %s, want it polled until active", host)
		assert.Equal(t, "new-1", h.fake.AssocCertID(host), "%s association", host)
	}
	assert.Zero(t, countIn(reqs, http.MethodDelete, ""), "DELETEs")

	for _, want := range []string{
		"They no longer use: old-1, old-2",
		"aopctl hostname prune --cert-id old-1 --cert-id old-2 --hostname a.example.com --hostname b.example.com --hostname c.example.com --hostname d.example.com",
	} {
		assert.Contains(t, stdout, want)
	}
}

func TestHostnameIssueFailures(t *testing.T) {
	t.Run("no free slot", func(t *testing.T) {
		h := issueHarness(t)
		for i := range 8 {
			h.fake.AddCert("spare-"+string(rune('a'+i)), h.ca.issue(t))
		}
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "the zone has 10 hostname certificates")
		assert.Empty(t, h.fake.Writes(), "write requests")
	})

	t.Run("upload transport error", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			cftest.ResetConnection(t, w)
			return true
		}
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "upload outcome unknown")
		assert.Contains(t, stderr, "aopctl hostname status before retrying")
		assert.NotContains(t, stderr, "To resume", "printed recovery commands without a certificate ID")
		assert.Zero(t, h.fake.Count(http.MethodPut, "/hostnames"), "PUTs")
	})

	t.Run("upload body cut off", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			cftest.WriteCutOff(t, w, http.StatusOK)
			return true
		}
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "upload outcome unknown")
		assert.Contains(t, stderr, "HTTP 200: unexpected EOF")
		assert.Zero(t, h.fake.Count(http.MethodPut, "/hostnames"), "PUTs")
	})

	t.Run("upload result with an undecodable ID", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			cftest.WriteEnvelope(w, http.StatusOK, map[string]any{"id": 1, "status": "initializing"}, nil)
			return true
		}
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "upload outcome unknown")
		assert.Contains(t, stderr, "aopctl hostname status before retrying")
		assert.Zero(t, h.fake.Count(http.MethodPut, "/hostnames"), "PUTs")
	})

	t.Run("upload rejected", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPost {
				return false
			}
			cftest.WriteAPIError(w, http.StatusBadRequest, 1400, "missing leaf certificate")
			return true
		}
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "upload failed")
		assert.NotContains(t, stderr, "outcome unknown")
		assert.Zero(t, h.fake.Count(http.MethodPut, "/hostnames"), "PUTs")
	})

	// A server error or an unsuccessful 2xx may follow a create that
	// happened.
	for _, tt := range []struct {
		name   string
		status int
		body   string
	}{
		{"upload server error", http.StatusInternalServerError, `{"success":false,"errors":[{"code":1000,"message":"internal error"}],"messages":[],"result":null}`},
		{"upload unsuccessful 200", http.StatusOK, `{"success":false,"errors":[{"code":1000,"message":"internal error"}],"messages":[],"result":null}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := issueHarness(t)
			h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
				if r.Method != http.MethodPost {
					return false
				}
				cftest.WriteRaw(w, tt.status, "application/json", tt.body)
				return true
			}
			code, _, stderr := h.run("hostname", "issue")
			assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, "upload outcome unknown")
			assert.Contains(t, stderr, "aopctl hostname status before retrying")
			assert.Zero(t, h.fake.Count(http.MethodPut, "/hostnames"), "PUTs")
		})
	}

	t.Run("certificate never active", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.UploadStatuses = []string{"pending_deployment"}
		h.waitLimit = 3
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "timed out waiting for certificate new-1 to become active: last status pending_deployment")
		assert.Zero(t, h.fake.Count(http.MethodPut, "/hostnames"), "PUTs")
	})

	t.Run("deployment timed out", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.UploadStatuses = []string{"pending_deployment", cftest.StatusDeploymentTimedOut}
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "certificate new-1 is deployment_timed_out")
		assert.Contains(t, stderr, "New certificate: new-1")
		assert.Zero(t, h.fake.Count(http.MethodPut, "/hostnames"), "PUTs")
		// hostname associate refuses a certificate that is not active, and no
		// hostname changed, so there is nothing to resume or roll back.
		for _, unwanted := range []string{"To resume", "To roll back"} {
			assert.NotContains(t, stderr, unwanted)
		}
		hosts := " --hostname a.example.com --hostname b.example.com --hostname c.example.com --hostname d.example.com\n"
		for _, want := range []string{
			"No hostname was changed.",
			"If certificate new-1 becomes active later",
			"aopctl hostname associate --cert-id new-1" + hosts,
			"aopctl hostname prune --cert-id new-1" + hosts,
		} {
			assert.Contains(t, stderr, want)
		}

		prune := commandLines(stderr, "aopctl hostname prune --cert-id new-1")
		require.Len(t, prune, 1, "prune commands")
		h.openTTY = func() (io.ReadWriteCloser, error) { return &fakeTTY{Reader: strings.NewReader("y\n")}, nil }
		code, _, stderr = h.run(prune[0]...)
		require.Equal(t, 0, code, "prune: exit code; stderr:\n%s", stderr)
		assert.Equal(t, "new-1", strings.Join(deletes(h), ","), "deleted")
	})

	t.Run("PUT fails", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPut {
				return false
			}
			cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
			return true
		}
		code, _, stderr := h.run("hostname", "issue")
		require.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		// A PUT is not a polling read, so a 5xx is not retried.
		assert.Equal(t, 1, h.fake.Count(http.MethodPut, "/hostnames"), "PUTs")
		for _, want := range []string{
			"New certificate: new-1",
			"aopctl hostname associate --cert-id new-1 --hostname a.example.com --hostname b.example.com --hostname c.example.com --hostname d.example.com",
			"aopctl hostname associate --cert-id old-1 --hostname a.example.com --hostname b.example.com",
			"aopctl hostname associate --cert-id old-2 --hostname c.example.com",
		} {
			assert.Contains(t, stderr, want)
		}
	})

	t.Run("association never active", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.AssocStatuses = []string{"pending_deployment"}
		h.waitLimit = 4
		code, _, stderr := h.run("hostname", "issue")
		require.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		for _, want := range []string{
			"timed out waiting for hostnames to use certificate new-1",
			hostA + ": new-1 (enabled=true, status=pending_deployment)",
			"To resume, run:",
		} {
			assert.Contains(t, stderr, want)
		}
	})

	t.Run("preflight association error", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/hostnames/"+hostB) {
				cftest.WriteAPIError(w, http.StatusNotFound, 1000, "not found")
				return true
			}
			return false
		}
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "read association for b.example.com")
		assert.Empty(t, h.fake.Writes(), "write requests")
	})

	t.Run("preflight association without a cert_id", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/hostnames/"+hostD) {
				cftest.WriteRaw(w, http.StatusOK, "application/json", `{"success":true,"errors":[],"messages":[],"result":null}`)
				return true
			}
			return false
		}
		h.waitLimit = 20
		code, _, stderr := h.run("hostname", "issue")
		require.Empty(t, h.fake.Writes(), "write requests")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "read association for d.example.com")
	})

	t.Run("disabled hostname", func(t *testing.T) {
		h := issueHarness(t)
		h.fake.SetAssoc(hostC, "old-2", new(false))
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "c.example.com has AOP disabled")
		assert.Empty(t, h.fake.Writes(), "write requests")
	})
}

// A response to the upload whose other fields drifted still yields the ID.
func TestHostnameIssueUploadDrift(t *testing.T) {
	h := issueHarness(t)
	h.fake.Hook = func(w http.ResponseWriter, r *http.Request, body []byte) bool {
		if r.Method != http.MethodPost {
			return false
		}
		h.fake.Upload(httptest.NewRecorder(), body)
		cftest.WriteEnvelope(w, http.StatusOK, map[string]any{"id": "new-1", "status": "initializing", "expires_on": 1893456000}, nil)
		return true
	}
	code, stdout, stderr := h.run("hostname", "issue")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	reqs := h.fake.Recorded()
	assert.GreaterOrEqual(t, countIn(requestsAfter(reqs, http.MethodPost, "/certificates"), http.MethodGet, "/certificates/new-1"), 2,
		"polls of new-1 after the upload, want it polled to active")
	assert.Contains(t, stdout, "now use certificate new-1")
}

// TestHostnameIssueTransientPolling covers polling reads that fail with HTTP 429
// or a 5xx.
func TestHostnameIssueTransientPolling(t *testing.T) {
	// failFirst answers the first len(statuses) GETs whose path ends in suffix
	// with those statuses, after a PUT when afterPut is set.
	failFirst := func(h *harness, suffix string, afterPut bool, statuses ...int) {
		put := false
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodPut {
				put = true
			}
			if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, suffix) || (afterPut && !put) || len(statuses) == 0 {
				return false
			}
			status := statuses[0]
			statuses = statuses[1:]
			if status == http.StatusTooManyRequests {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "rate limited")
				return true
			}
			cftest.WriteAPIError(w, status, 1000, "temporarily unavailable")
			return true
		}
	}

	t.Run("certificate polling recovers", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		failFirst(h, "/certificates/new-1", false, http.StatusServiceUnavailable, http.StatusTooManyRequests)
		code, _, stderr := h.run("hostname", "issue")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, "new-1", h.fake.AssocCertID(hostA), "%s association", hostA)
	})

	t.Run("association polling recovers", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		failFirst(h, "/hostnames/"+hostA, true, http.StatusServiceUnavailable, http.StatusTooManyRequests)
		code, _, stderr := h.run("hostname", "issue")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.GreaterOrEqual(t, countIn(requestsAfter(h.fake.Recorded(), http.MethodPut, "/hostnames"), http.MethodGet, "/hostnames/"+hostA), 4,
			"polls of %s after the PUT, want the two failures retried", hostA)
	})

	t.Run("budget runs out", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 3
		failFirst(h, "/certificates/new-1", false, http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable)
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "timed out waiting for certificate new-1 to become active: last error: GET /zones/{zone}/origin_tls_client_auth/hostnames/certificates/new-1: HTTP 503")
		assert.Equal(t, 3, h.fake.Count(http.MethodGet, "/certificates/new-1"), "polls")
	})

	t.Run("other errors fail at once", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		failFirst(h, "/certificates/new-1", false, http.StatusBadRequest)
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "check certificate new-1: GET /zones/{zone}/origin_tls_client_auth/hostnames/certificates/new-1: HTTP 400")
		assert.Equal(t, 1, h.fake.Count(http.MethodGet, "/certificates/new-1"), "polls")
	})
}

// TestPollingIncompleteResponses covers polling reads that get no complete
// response, which are retried, and a complete but malformed one, which is
// not.
func TestPollingIncompleteResponses(t *testing.T) {
	// failGets answers the first n GETs whose path ends in suffix with
	// respond, once a request with method after has been seen. It returns a
	// count of the GETs it answered.
	failGets := func(h *harness, after, suffix string, n int, respond func(http.ResponseWriter)) func() int {
		seen, failed := false, 0
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == after {
				seen = true
			}
			if !seen || r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, suffix) || failed == n {
				return false
			}
			failed++
			respond(w)
			return true
		}
		return func() int {
			h.fake.Mu.Lock()
			defer h.fake.Mu.Unlock()
			return failed
		}
	}

	for _, tt := range []struct {
		name      string
		setup     func(*testing.T) *harness
		args      []string
		after     string
		afterPath string
		suffix    string
	}{
		{"certificate", issueHarness, []string{"hostname", "issue"}, http.MethodPost, "/certificates", "/certificates/new-1"},
		{"association", issueHarness, []string{"hostname", "issue"}, http.MethodPut, "/hostnames", "/hostnames/" + hostA},
		{"deletion", pruneHarness, []string{"hostname", "prune", "--cert-id", "old", "--yes"}, http.MethodDelete, "/certificates/old", "/certificates/old"},
	} {
		t.Run(tt.name+" polling recovers from a cut-off body", func(t *testing.T) {
			h := tt.setup(t)
			h.waitLimit = 20
			failed := failGets(h, tt.after, tt.suffix, 1, func(w http.ResponseWriter) { cftest.WriteCutOff(t, w, http.StatusOK) })
			code, _, stderr := h.run(tt.args...)
			require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
			require.Equal(t, 1, failed(), "cut-off bodies")
			// The cut-off read, then at least two polls to finish.
			assert.GreaterOrEqual(t, countIn(requestsAfter(h.fake.Recorded(), tt.after, tt.afterPath), http.MethodGet, tt.suffix), 3,
				"polls after the %s, want the cut-off read retried", tt.after)
		})
	}

	t.Run("certificate polling recovers from a reset connection", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		// Go's transport resends an idempotent request when a reused
		// connection closes before the response, so the fake resets twice
		// to make sure aopctl sees the error.
		failGets(h, http.MethodPost, "/certificates/new-1", 2, func(w http.ResponseWriter) { cftest.ResetConnection(t, w) })
		code, _, stderr := h.run("hostname", "issue")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		// One wait each for the certificate and the associations, plus the
		// retry.
		assert.GreaterOrEqual(t, h.waits, 3, "waits, want a retry after the reset")
	})

	t.Run("a malformed response fails at once", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		failGets(h, http.MethodPost, "/certificates/new-1", 1, func(w http.ResponseWriter) {
			cftest.WriteRaw(w, http.StatusOK, "text/html", "<html>maintenance</html>")
		})
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, `check certificate new-1: GET /zones/{zone}/origin_tls_client_auth/hostnames/certificates/new-1: HTTP 200: undecodable response (content type "text/html")`)
		assert.Equal(t, 1, h.fake.Count(http.MethodGet, "/certificates/new-1"), "polls")
	})
}

func TestHostnameIssueAssociationTimedOut(t *testing.T) {
	t.Run("stale on the old certificate", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		// hostA still reports old-1, timed out, for two polls after the PUT.
		put, stale := false, 0
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodPut {
				put = true
				return false
			}
			if !put || r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/hostnames/"+hostA) || stale == 2 {
				return false
			}
			stale++
			cftest.WriteEnvelope(w, http.StatusOK, map[string]any{
				"hostname": hostA, "cert_id": "old-1", "enabled": true, "status": cftest.StatusDeploymentTimedOut,
			}, nil)
			return true
		}
		code, _, stderr := h.run("hostname", "issue")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, "new-1", h.fake.AssocCertID(hostA), "%s association", hostA)
	})

	t.Run("timed out on the new certificate", func(t *testing.T) {
		h := issueHarness(t)
		h.waitLimit = 20
		h.fake.AssocStatuses = []string{"pending_deployment", cftest.StatusDeploymentTimedOut}
		code, _, stderr := h.run("hostname", "issue")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "association for a.example.com is deployment_timed_out")
		assert.Equal(t, 2, h.waits, "waits, want one for the certificate and one for the associations")
	})
}

// commandLines returns the printed aopctl commands that start with prefix,
// as argument lists without "aopctl".
func commandLines(output, prefix string) [][]string {
	var cmds [][]string
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			cmds = append(cmds, strings.Fields(line)[1:])
		}
	}
	return cmds
}

func TestHostnameIssueLastSlotRecovery(t *testing.T) {
	h := issueHarness(t)
	for i := range 7 {
		h.fake.AddCert("spare-"+string(rune('a'+i)), h.ca.issue(t))
	}
	h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodPut {
			return false
		}
		cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
		return true
	}
	code, _, stderr := h.run("hostname", "issue")
	require.Equal(t, 1, code, "issue: exit code; stderr:\n%s", stderr)
	resume := commandLines(stderr, "aopctl hostname associate --cert-id new-1")
	require.Len(t, resume, 1, "resume commands")

	h.fake.Hook = nil
	before := len(h.fake.Recorded())
	code, _, stderr = h.run(resume[0]...)
	require.Equal(t, 0, code, "resume: exit code; stderr:\n%s", stderr)
	for _, host := range []string{hostA, hostB, hostC, hostD} {
		assert.Equal(t, "new-1", h.fake.AssocCertID(host), "%s association", host)
	}
	assert.Zero(t, countIn(h.fake.Recorded()[before:], http.MethodGet, "/certificates"), "resume listed certificates; it must not need a free slot")
}

func TestHostnameIssueRollbackOutput(t *testing.T) {
	h := issueHarness(t)
	// The PUT applies to hostA and hostC only, then fails.
	h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
		if r.Method != http.MethodPut {
			return false
		}
		h.fake.ApplyAssociation(hostA, "new-1", new(true))
		h.fake.ApplyAssociation(hostC, "new-1", new(true))
		cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
		return true
	}
	code, _, stderr := h.run("hostname", "issue")
	require.Equal(t, 1, code, "issue: exit code; stderr:\n%s", stderr)
	for _, want := range []string{
		hostA + ": old-1 (enabled=true, status=active) -> new-1 (enabled=true, status=pending_deployment)",
		hostB + ": old-1 (enabled=true, status=active) -> old-1 (enabled=true, status=active)",
		hostD + ": none -> none",
		`{"config":[{"hostname":"d.example.com","cert_id":"new-1","enabled":null}]}`,
		"PUT /zones/{zone}/origin_tls_client_auth/hostnames",
		"Cloudflare dashboard",
	} {
		assert.Contains(t, stderr, want)
	}
	rollback := commandLines(stderr, "aopctl hostname associate --cert-id old-")
	got := make([]string, len(rollback))
	for i, args := range rollback {
		got[i] = strings.Join(args, " ")
	}
	want := []string{
		"hostname associate --cert-id old-1 --hostname a.example.com --hostname b.example.com",
		"hostname associate --cert-id old-2 --hostname c.example.com",
	}
	require.Equal(t, want, got, "rollback commands")

	h.fake.Hook = nil
	for _, args := range rollback {
		code, _, stderr := h.run(args...)
		require.Equal(t, 0, code, "%v: exit code; stderr:\n%s", args, stderr)
	}
	for host, want := range map[string]string{hostA: "old-1", hostB: "old-1", hostC: "old-2", hostD: ""} {
		assert.Equal(t, want, h.fake.AssocCertID(host), "%s association after rollback", host)
	}
}

// TestHostnameIssueOtherCA covers a CA rotation: AOP_CA_CERT is the new CA, and
// old-1 was signed by the old one.
func TestHostnameIssueOtherCA(t *testing.T) {
	setup := func(t *testing.T) (*harness, *testCA) {
		h := newHarness(t)
		oldCA := newTestCA(t, 3650)
		h.fake.AddCert("old-1", oldCA.issue(t))
		h.fake.AddCert("cur-1", h.ca.issue(t))
		h.fake.SetAssoc(hostA, "old-1", new(true))
		h.fake.SetAssoc(hostB, "cur-1", new(true))
		h.env["AOP_HOSTNAMES"] = hostA + "," + hostB
		return h, oldCA
	}

	t.Run("rollback", func(t *testing.T) {
		h, oldCA := setup(t)
		// The PUT applies to hostA only, then fails.
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodPut {
				return false
			}
			h.fake.ApplyAssociation(hostA, "new-1", new(true))
			cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
			return true
		}
		code, _, stderr := h.run("hostname", "issue")
		require.Equal(t, 1, code, "issue: exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "AOP_CA_CERT did not sign old-1, so run the next command with AOP_CA_CERT set to the CA that did",
			"rollback lacks the other-CA note for old-1")
		assert.NotContains(t, stderr, "did not sign cur-1", "rollback has an other-CA note for cur-1")
		rollback := commandLines(stderr, "aopctl hostname associate --cert-id old-1")
		require.Len(t, rollback, 1, "rollback commands for old-1")

		h.fake.Hook = nil
		code, _, stderr = h.run(rollback[0]...)
		assert.Equal(t, 1, code, "with the new CA: exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "certificate old-1 is not signed by AOP_CA_CERT", "with the new CA")
		assert.Equal(t, "new-1", h.fake.AssocCertID(hostA), "%s association after a refused rollback", hostA)

		h.env["AOP_CA_CERT"] = oldCA.certPEM
		code, _, stderr = h.run(rollback[0]...)
		require.Equal(t, 0, code, "with the old CA: exit code; stderr:\n%s", stderr)
		assert.Equal(t, "old-1", h.fake.AssocCertID(hostA), "%s association after rollback", hostA)
	})

	t.Run("prune hint", func(t *testing.T) {
		h, _ := setup(t)
		code, stdout, stderr := h.run("hostname", "issue")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		for _, want := range []string{
			"aopctl hostname prune --cert-id cur-1 --hostname a.example.com --hostname b.example.com\n",
			"AOP_CA_CERT did not sign old-1, so run the next command with AOP_CA_CERT set to the CA that did",
			"aopctl hostname prune --cert-id old-1 --hostname a.example.com --hostname b.example.com\n",
		} {
			assert.Contains(t, stdout, want)
		}
	})
}

func TestHostnameAssociate(t *testing.T) {
	setup := func(t *testing.T) *harness {
		h := newHarness(t)
		h.fake.AddCert("good", h.ca.issue(t))
		h.fake.AddCert("foreign", newTestCA(t, 3650).issue(t))
		h.fake.AddCert("deploying", h.ca.issue(t), "pending_deployment")
		h.env["AOP_HOSTNAMES"] = hostA + " " + hostB
		h.fake.SetAssoc(hostA, "old", new(true))
		return h
	}

	for _, tt := range []struct{ id, want string }{
		{"foreign", "certificate foreign is not signed by AOP_CA_CERT"},
		{"deploying", "certificate deploying is pending_deployment, not active"},
		{"missing", "HTTP 404"},
	} {
		t.Run("refuses "+tt.id, func(t *testing.T) {
			h := setup(t)
			code, _, stderr := h.run("hostname", "associate", "--cert-id", tt.id)
			assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, tt.want)
			assert.Empty(t, h.fake.Writes(), "write requests")
		})
	}

	t.Run("refuses a disabled hostname", func(t *testing.T) {
		h := setup(t)
		h.fake.SetAssoc(hostB, "old", new(false))
		code, _, stderr := h.run("hostname", "associate", "--cert-id", "good")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "b.example.com has AOP disabled")
		assert.Empty(t, h.fake.Writes(), "write requests")
	})

	t.Run("dry run", func(t *testing.T) {
		h := setup(t)
		code, _, stderr := h.run("hostname", "associate", "--cert-id", "good", "--dry-run")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, hostA+": old (enabled=true, status=active) -> good")
		assert.Contains(t, stderr, hostB+": none -> good")
		assert.Empty(t, h.fake.Writes(), "write requests")
	})

	t.Run("associates", func(t *testing.T) {
		h := setup(t)
		code, stdout, stderr := h.run("hostname", "associate", "--cert-id", "good")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		reqs := h.fake.Recorded()
		if w := h.fake.Writes(); assert.Len(t, w, 1, "writes, want one PUT") {
			assert.Equal(t, http.MethodPut, w[0].Method, "write method")
		}
		afterPut := requestsAfter(reqs, http.MethodPut, "/hostnames")
		for _, host := range []string{hostA, hostB} {
			assert.GreaterOrEqual(t, countIn(afterPut, http.MethodGet, "/hostnames/"+host), 2, "polls of %s, want it polled until active", host)
			assert.Equal(t, "good", h.fake.AssocCertID(host), "%s association", host)
		}
		assert.Contains(t, stdout, "now use certificate good")
	})
}

func TestHostnameStatus(t *testing.T) {
	h := newHarness(t)
	minePEM := h.ca.issue(t)
	h.fake.AddCert("mine", minePEM)
	h.fake.AddCert("foreign", newTestCA(t, 3650).issue(t))
	h.fake.SetAssoc(hostA, "mine", new(true))
	h.env["AOP_HOSTNAMES"] = hostA + "," + hostB
	mineCert, err := aopctl.ParseCertificatePEM(minePEM)
	require.NoError(t, err)

	code, stdout, stderr := h.run("hostname", "status")
	require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
	mine, foreign, _ := strings.Cut(strings.SplitN(stdout, "  mine\n", 2)[1], "  foreign\n")
	for _, want := range []string{"status:    active", "subject:   existing leaf", "key type:  ECDSA P-256", "days left", "signed by AOP_CA_CERT: yes", "used by:   a.example.com", "fingerprint: " + aopctl.Fingerprint(mineCert)} {
		assert.Contains(t, mine, want, "mine")
	}
	assert.Contains(t, foreign, "signed by AOP_CA_CERT: no", "foreign")
	assert.Contains(t, foreign, "used by:   none of the listed hostnames", "foreign")
	for _, want := range []string{hostA + ": mine (enabled=true, status=active)", hostB + ": none", "cannot be discovered"} {
		assert.Contains(t, stdout, want)
	}

	delete(h.env, "AOP_CA_CERT")
	_, stdout, _ = h.run("hostname", "status")
	assert.Contains(t, stdout, "signed by AOP_CA_CERT: unknown", "without AOP_CA_CERT")
}

// pruneHarness has hostA on "used", and "old" and "spare" unused.
func pruneHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.fake.AddCert("used", h.ca.issue(t))
	h.fake.AddCert("old", h.ca.issue(t))
	h.fake.AddCert("spare", h.ca.issue(t))
	h.fake.SetAssoc(hostA, "used", new(true))
	h.env["AOP_HOSTNAMES"] = hostA + "," + hostB
	return h
}

func deletes(h *harness) []string {
	var ids []string
	for _, r := range h.fake.Recorded() {
		if r.Method == http.MethodDelete {
			ids = append(ids, r.Path[strings.LastIndex(r.Path, "/")+1:])
		}
	}
	return ids
}

func TestHostnamePruneRefusals(t *testing.T) {
	t.Run("no cert id", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("hostname", "prune")
		assert.Equal(t, 2, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "aopctl hostname status")
	})

	t.Run("no hostnames", func(t *testing.T) {
		h := pruneHarness(t)
		delete(h.env, "AOP_HOSTNAMES")
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "no hostnames")
		assert.Empty(t, h.fake.Recorded(), "requests sent")
	})

	t.Run("in use", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "used", "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Refused used: still used by a.example.com")
		assert.Empty(t, deletes(h), "deleted")
	})

	t.Run("other CA", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.AddCert("foreign", newTestCA(t, 3650).issue(t))
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "foreign", "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Refused foreign: certificate foreign is not signed by AOP_CA_CERT")
		assert.Empty(t, deletes(h), "deleted")
	})

	t.Run("not found", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "missing", "--cert-id", "old", "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Refused missing: not found")
		assert.Equal(t, "old", strings.Join(deletes(h), ","), "deleted, want old only")
	})

	t.Run("preflight association error", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/hostnames/"+hostB) {
				cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
				return true
			}
			return false
		}
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "read association for b.example.com")
		assert.Empty(t, deletes(h), "deleted")
	})

	for _, result := range []string{"null", "{}"} {
		t.Run("association result "+result, func(t *testing.T) {
			h := pruneHarness(t)
			h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/hostnames/"+hostB) {
					cftest.WriteRaw(w, http.StatusOK, "application/json", `{"success":true,"errors":[],"messages":[],"result":`+result+`}`)
					return true
				}
				return false
			}
			code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes")
			require.Empty(t, deletes(h), "deleted after an association read without a cert_id")
			assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, "read association for b.example.com: GET /zones/{zone}/origin_tls_client_auth/hostnames/b.example.com: HTTP 200: association result has no cert_id")
		})
	}

	t.Run("only named ids", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes")
		require.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, "old", strings.Join(deletes(h), ","), "deleted, want old only")
		assert.Contains(t, stderr, pruneWarning, "preview lacks the hostname-scope warning")
		assert.Contains(t, stderr, "old  existing leaf, expires ", "preview lacks the certificate")
	})
}

func TestHostnamePruneChangeAfterPreview(t *testing.T) {
	// changeOnReread lets the first read of hostB through and handles the
	// second, which happens just before the DELETE.
	changeOnReread := func(h *harness, second func(w http.ResponseWriter) bool) {
		reads := 0
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/hostnames/"+hostB) {
				return false
			}
			reads++
			if reads == 2 {
				return second(w)
			}
			return false
		}
	}

	t.Run("now associated", func(t *testing.T) {
		h := pruneHarness(t)
		changeOnReread(h, func(http.ResponseWriter) bool {
			h.fake.Assocs[hostB] = &cftest.Assoc{CertID: "old", Enabled: new(true), Statuses: []string{cftest.StatusActive}}
			return false
		})
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes")
		require.Empty(t, deletes(h), "deleted after the certificate came into use")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Refused old: now used by b.example.com")
	})

	t.Run("re-read fails", func(t *testing.T) {
		h := pruneHarness(t)
		changeOnReread(h, func(w http.ResponseWriter) bool {
			cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
			return true
		})
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes")
		require.Empty(t, deletes(h), "deleted after the re-read failed")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Failed old: read association for b.example.com")
	})
}

func TestHostnamePruneConfirmation(t *testing.T) {
	for _, tt := range []struct {
		answer string
		delete bool
	}{
		{"y\n", true},
		{"YES\n", true},
		{"n\n", false},
		{"\n", false},
		{"", false},
		{"yes please\n", false},
		// EOF before a newline aborts, whatever was typed.
		{"y", false},
		{"yes", false},
	} {
		t.Run(strconv.Quote(tt.answer), func(t *testing.T) {
			h := pruneHarness(t)
			tty := &fakeTTY{Reader: strings.NewReader(tt.answer)}
			h.openTTY = func() (io.ReadWriteCloser, error) { return tty, nil }
			code, _, stderr := h.run("hostname", "prune", "--cert-id", "old")
			assert.Contains(t, tty.prompt.String(), "Delete 1 certificate(s)? [y/N]", "prompt")
			d := deletes(h)
			if tt.delete {
				assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
				assert.Equal(t, "old", strings.Join(d, ","), "deleted")
				return
			}
			assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
			assert.Empty(t, d, "deleted")
			assert.Contains(t, stderr, "aborted")
		})
	}

	t.Run("interrupt", func(t *testing.T) {
		h := pruneHarness(t)
		tty := newBlockingTTY()
		h.openTTY = func() (io.ReadWriteCloser, error) { return tty, nil }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-tty.prompted
			cancel()
		}()
		type result struct {
			code   int
			stderr string
		}
		done := make(chan result, 1)
		go func() {
			code, _, stderr := h.runContext(ctx, "hostname", "prune", "--cert-id", "old")
			done <- result{code, stderr}
		}()
		var r result
		select {
		case r = <-done:
		case <-time.After(10 * time.Second):
			require.FailNow(t, "still waiting for an answer 10s after the interrupt")
		}
		assert.Equal(t, 1, r.code, "exit code; stderr:\n%s", r.stderr)
		assert.True(t, strings.HasSuffix(r.stderr, "aopctl: aborted: nothing deleted\n"), "stderr:\n%s", r.stderr)
		assert.Empty(t, deletes(h), "deleted")
		select {
		case <-tty.closed:
		default:
			assert.Fail(t, "left the terminal open")
		}
	})

	t.Run("no terminal", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "--yes")
		assert.Empty(t, deletes(h), "deleted")
	})

	t.Run("yes skips the prompt", func(t *testing.T) {
		h := pruneHarness(t)
		h.openTTY = func() (io.ReadWriteCloser, error) {
			assert.Fail(t, "opened the terminal despite --yes")
			return nil, io.EOF
		}
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Equal(t, "old", strings.Join(deletes(h), ","), "deleted")
	})
}

func TestHostnamePruneCompletion(t *testing.T) {
	t.Run("pending then gone", func(t *testing.T) {
		h := pruneHarness(t)
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Deleted old")
		assert.GreaterOrEqual(t, h.fake.Count(http.MethodGet, "/certificates/old"), 3, "polls, want polling until gone")
	})

	t.Run("deletion timed out", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.DeleteStatuses = []string{cftest.StatusPendingDeletion, cftest.StatusDeletionTimedOut}
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Failed old: the delete failed at Cloudflare: status deletion_timed_out")
	})

	t.Run("mixed results", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/old") {
				cftest.WriteAPIError(w, http.StatusInternalServerError, 1000, "internal error")
				return true
			}
			return false
		}
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--cert-id", "spare", "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Failed old")
		assert.Contains(t, stderr, "Deleted spare")
		assert.Equal(t, "old,spare", strings.Join(deletes(h), ","), "deleted")
	})

	t.Run("non-JSON 404 while deleting", func(t *testing.T) {
		h := pruneHarness(t)
		// After old's DELETE, an intermediary answers its GETs with an HTML
		// 404. spare's GETs reach Cloudflare's own 404 once it is gone.
		deleted := false
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if !strings.HasSuffix(r.URL.Path, "/certificates/old") {
				return false
			}
			if r.Method == http.MethodDelete {
				deleted = true
			}
			if !deleted || r.Method != http.MethodGet {
				return false
			}
			cftest.WriteRaw(w, http.StatusNotFound, "text/html", "<html>Not Found</html>")
			return true
		}
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--cert-id", "spare", "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, `Failed old: check certificate: GET /zones/{zone}/origin_tls_client_auth/hostnames/certificates/old: HTTP 404: undecodable response (content type "text/html")`)
		assert.NotContains(t, stderr, "Deleted old", "an HTML 404 counted as deleted")
		assert.Contains(t, stderr, "Deleted spare", "a Cloudflare 404 did not count as deleted")
	})

	t.Run("non-JSON 404 before deleting", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.Hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/certificates/old") {
				return false
			}
			cftest.WriteRaw(w, http.StatusNotFound, "text/html", "<html>Not Found</html>")
			return true
		}
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes")
		assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "read certificate old: ")
		assert.NotContains(t, stderr, "Refused old: not found")
		assert.Empty(t, deletes(h), "deleted")
	})

	t.Run("already deleted", func(t *testing.T) {
		h := pruneHarness(t)
		h.fake.AddCert("done", h.ca.issue(t), cftest.StatusDeleted)
		code, _, stderr := h.run("hostname", "prune", "--cert-id", "done", "--yes")
		assert.Equal(t, 0, code, "exit code; stderr:\n%s", stderr)
		assert.Contains(t, stderr, "Already deleted: done")
		assert.Empty(t, deletes(h), "deleted")
	})

	for _, tt := range []struct {
		name      string
		statuses  []string
		waitLimit int
		code      int
		want      string
	}{
		{"already pending, then gone", []string{cftest.StatusPendingDeletion, cftest.StatusPendingDeletion, "gone"}, 0, 0, "Deleted pending"},
		{"already pending, then timed out", []string{cftest.StatusPendingDeletion, cftest.StatusDeletionTimedOut}, 0, 1, "status deletion_timed_out"},
		{"already pending, budget runs out", []string{cftest.StatusPendingDeletion}, 3, 1, "timed out waiting for the delete to finish: last status pending_deletion"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := pruneHarness(t)
			h.fake.AddCert("pending", h.ca.issue(t), tt.statuses...)
			h.waitLimit = tt.waitLimit
			// No --yes and no terminal: a certificate that needs no DELETE
			// needs no confirmation.
			code, _, stderr := h.run("hostname", "prune", "--cert-id", "pending")
			assert.Equal(t, tt.code, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, tt.want)
			assert.Empty(t, deletes(h), "deleted")
		})
	}
}

// TestBudgetRunsOut runs commands under a real --timeout that ends either in
// a poll wait or while a polling read is in flight. Either way, the error
// reports the last observed state, not the context error.
func TestBudgetRunsOut(t *testing.T) {
	const budget = "250ms"
	// errorLine returns the command's error, without the recovery report.
	errorLine := func(stderr string) string {
		for line := range strings.SplitSeq(stderr, "\n") {
			if strings.HasPrefix(line, "aopctl: ") {
				return line
			}
		}
		return ""
	}
	// stallAfter stalls the GETs whose path ends in suffix once write has
	// been sent and skip of them have been answered.
	stallAfter := func(h *harness, write, suffix string, skip int) {
		written := false
		reads := 0
		h.fake.Hook = func(_ http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == write {
				written = true
			}
			if !written || r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, suffix) {
				return false
			}
			reads++
			if reads <= skip {
				return false
			}
			cftest.Stall(r)
			return true
		}
	}

	for _, tt := range []struct {
		name  string
		setup func(h *harness)
	}{
		{"certificate, budget ends in a wait", func(h *harness) { h.blockWaits = true }},
		{"certificate, budget ends in a read", func(h *harness) { stallAfter(h, http.MethodPost, "/certificates/new-1", 1) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := issueHarness(t)
			h.fake.UploadStatuses = []string{"pending_deployment"}
			tt.setup(h)
			code, _, stderr := h.run("hostname", "issue", "--timeout", budget)
			require.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
			assert.Equal(t, "aopctl: timed out waiting for certificate new-1 to become active: last status pending_deployment", errorLine(stderr), "error")
			assert.Zero(t, h.fake.Count(http.MethodPut, "/hostnames"), "PUTs")
		})
	}

	pending := func(host string) string {
		return host + ": new-1 (enabled=true, status=pending_deployment)"
	}
	t.Run("association, budget ends in a wait", func(t *testing.T) {
		t.Parallel()
		h := issueHarness(t)
		h.fake.UploadStatuses = []string{cftest.StatusActive}
		h.fake.AssocStatuses = []string{"pending_deployment"}
		h.blockWaits = true
		code, _, stderr := h.run("hostname", "issue", "--timeout", budget)
		require.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		want := "aopctl: timed out waiting for hostnames to use certificate new-1: last observed " +
			strings.Join([]string{pending(hostA), pending(hostB), pending(hostC), pending(hostD)}, "; ")
		assert.Equal(t, want, errorLine(stderr), "error")
	})

	t.Run("association, budget ends in a read", func(t *testing.T) {
		t.Parallel()
		h := issueHarness(t)
		h.fake.AssocStatuses = []string{"pending_deployment"}
		// In the second round, hostA becomes active and the read of hostB
		// stalls.
		put := false
		reads := map[string]int{}
		h.fake.Hook = func(_ http.ResponseWriter, r *http.Request, _ []byte) bool {
			if r.Method == http.MethodPut {
				put = true
			}
			if !put || r.Method != http.MethodGet {
				return false
			}
			host := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			reads[host]++
			switch {
			case host == hostA && reads[host] == 2:
				h.fake.Assocs[hostA].Statuses = []string{cftest.StatusActive}
			case host == hostB && reads[host] == 2:
				cftest.Stall(r)
				return true
			}
			return false
		}
		code, _, stderr := h.run("hostname", "issue", "--timeout", budget)
		require.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
		want := "aopctl: timed out waiting for hostnames to use certificate new-1: last observed " +
			strings.Join([]string{pending(hostB), pending(hostC), pending(hostD)}, "; ")
		assert.Equal(t, want, errorLine(stderr), "error")
	})

	for _, tt := range []struct {
		name  string
		setup func(h *harness)
	}{
		{"deletion, budget ends in a wait", func(h *harness) { h.blockWaits = true }},
		{"deletion, budget ends in a read", func(h *harness) { stallAfter(h, http.MethodDelete, "/certificates/old", 1) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := pruneHarness(t)
			h.fake.DeleteStatuses = []string{cftest.StatusPendingDeletion}
			tt.setup(h)
			code, _, stderr := h.run("hostname", "prune", "--cert-id", "old", "--yes", "--timeout", budget)
			assert.Equal(t, 1, code, "exit code; stderr:\n%s", stderr)
			assert.Contains(t, stderr, "Failed old: timed out waiting for the delete to finish: last status pending_deletion\n")
			assert.Equal(t, "old", strings.Join(deletes(h), ","), "deleted, want old once")
		})
	}
}

func TestPagination(t *testing.T) {
	h := newHarness(t)
	h.fake.PerPage = 3
	for i := 1; i <= 10; i++ {
		h.fake.AddCert(fmt.Sprintf("cert-%02d", i), h.ca.issue(t))
	}

	code, stdout, stderr := h.run("hostname", "status")
	require.Equal(t, 0, code, "status: exit code; stderr:\n%s", stderr)
	assert.Contains(t, stdout, "Certificates (10 of 10)", "status misses later pages")
	assert.Contains(t, stdout, "cert-10", "status misses later pages")

	// cert-10 is alone on page 4, and it fills the last slot.
	code, _, stderr = h.run("hostname", "issue", "--hostname", "app.example.com")
	assert.Equal(t, 1, code, "issue: exit code; stderr:\n%s", stderr)
	assert.Contains(t, stderr, "the zone has 10 hostname certificates", "issue")
	assert.Zero(t, h.fake.Count(http.MethodPost, "/certificates"), "uploads")
	var pages []string
	for _, r := range h.fake.Recorded() {
		if r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/certificates") {
			pages = append(pages, r.Query)
		}
	}
	assert.Equal(t, "page=1 page=2 page=3 page=4 page=1 page=2 page=3 page=4", strings.Join(pages, " "), "list requests")
}
