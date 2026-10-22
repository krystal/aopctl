package aopctl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/krystal/aopctl/internal/cftest"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *cfClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &cfClient{baseURL: srv.URL, token: cftest.Token, zoneID: cftest.Zone, http: &http.Client{Timeout: requestTimeout}}
}

func TestClientSendsBearerToken(t *testing.T) {
	var auth, agent string
	cf := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		auth, agent = r.Header.Get("Authorization"), r.Header.Get("User-Agent")
		cftest.WriteEnvelope(w, http.StatusOK, []any{}, nil)
	})
	_, err := cf.listCerts(context.Background())
	require.NoError(t, err, "listCerts")
	assert.Equal(t, "Bearer "+cftest.Token, auth, "Authorization")
	assert.Equal(t, userAgent, agent, "User-Agent")
}

func TestClientErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{
			name: "non-2xx with success true",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				cftest.WriteRaw(w, http.StatusBadGateway, "application/json", `{"success":true,"errors":[],"messages":[],"result":[]}`)
			},
			want: "HTTP 502",
		},
		{
			name: "2xx with success false",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				cftest.WriteRaw(w, http.StatusOK, "application/json", `{"success":false,"errors":[{"code":1001,"message":"nope"}],"messages":[],"result":null}`)
			},
			want: "HTTP 200 (code 1001): request unsuccessful: nope",
		},
		{
			name: "malformed JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				cftest.WriteRaw(w, http.StatusOK, "application/json", `{"success":true,"result":[`)
			},
			want: `HTTP 200: undecodable response (content type "application/json")`,
		},
		{
			name: "non-JSON body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				cftest.WriteRaw(w, http.StatusBadGateway, "text/html", "<html>upstream secret page</html>")
			},
			want: `HTTP 502: undecodable response (content type "text/html")`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := newTestClient(t, tt.handler)
			_, err := cf.listCerts(context.Background())
			require.Error(t, err, "listCerts succeeded")
			assert.Contains(t, err.Error(), tt.want)
			assert.True(t, strings.HasPrefix(err.Error(), "GET /zones/{zone}/origin_tls_client_auth/hostnames/certificates"),
				"err does not name the redacted path: %q", err)
			assert.NotContains(t, err.Error(), "secret page", "err contains the response body")
		})
	}
}

// TestResponseClassification checks which failed responses polling retries
// and which count as a Cloudflare 404.
func TestResponseClassification(t *testing.T) {
	tests := []struct {
		name      string
		handler   http.HandlerFunc
		want      string
		transient bool
		notFound  bool
	}{
		{
			name:      "connection reset",
			handler:   func(w http.ResponseWriter, _ *http.Request) { cftest.ResetConnection(t, w) },
			transient: true,
		},
		{
			name:      "body cut off",
			handler:   func(w http.ResponseWriter, _ *http.Request) { cftest.WriteCutOff(t, w, http.StatusOK) },
			want:      "HTTP 200: unexpected EOF",
			transient: true,
		},
		{
			name: "no success field",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				cftest.WriteRaw(w, http.StatusOK, "application/json", `{"result":{"id":"x"}}`)
			},
			want: `HTTP 200: undecodable response (content type "application/json")`,
		},
		{
			name: "too large",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				body := `{"success":true,"errors":[],"messages":[],"result":{}}`
				cftest.WriteRaw(w, http.StatusOK, "application/json", body+strings.Repeat(" ", maxResponseBytes+1-len(body)))
			},
			want: `HTTP 200: response too large (content type "application/json")`,
		},
		{
			name: "non-JSON 503",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				cftest.WriteRaw(w, http.StatusServiceUnavailable, "text/html", "<html>busy</html>")
			},
			want:      "HTTP 503: undecodable response",
			transient: true,
		},
		{
			name: "non-JSON 404",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				cftest.WriteRaw(w, http.StatusNotFound, "text/html", "<html>Not Found</html>")
			},
			want: "HTTP 404: undecodable response",
		},
		{
			name: "Cloudflare 404",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				cftest.WriteAPIError(w, http.StatusNotFound, 1551, "certificate not found")
			},
			want:     "HTTP 404 (code 1551): certificate not found",
			notFound: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := newTestClient(t, tt.handler)
			_, err := cf.getCert(context.Background(), "x")
			require.Error(t, err, "getCert succeeded")
			assert.Contains(t, err.Error(), tt.want)
			assert.NotContains(t, err.Error(), cftest.Zone, "err contains the zone ID")
			assert.Equal(t, tt.transient, isTransient(err), "isTransient")
			assert.Equal(t, tt.notFound, isNotFound(err), "isNotFound")
		})
	}
}

// TestErrorsRedactSecrets uses a server that echoes the request body, the
// token and the zone ID back in the envelope's messages.
func TestErrorsRedactSecrets(t *testing.T) {
	ca := newTestCA(t, 3650)
	leaf, key, err := createLeaf(ca.cert, ca.key, "leaf", KeyTypeECP256, 30, time.Now())
	require.NoError(t, err, "createLeaf")
	keyPEM, err := EncodePrivateKeyPEM(key)
	require.NoError(t, err, "encodeKeyPEM")

	cf := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		zone := strings.Split(r.URL.Path, "/")[2]
		echo := fmt.Sprintf("body=%s token=%s zone=%s", body, token, zone)
		// A cut-off copy has no END line, and a bare copy has no PEM armor.
		cut := string(body[:len(body)-60])
		bare := strings.Join(strings.Split(keyPEM, "\n")[1:3], "")
		cftest.WriteEnvelope(w, http.StatusBadRequest, nil, map[string]any{
			"success":  false,
			"errors":   []any{map[string]any{"code": 1000, "message": echo}},
			"messages": []any{cut, map[string]any{"code": 0, "message": "key " + bare + " zone" + zone + "token" + token}},
		})
	})
	_, err = cf.uploadCert(context.Background(), EncodeCertificatePEM(leaf), keyPEM)
	require.Error(t, err, "uploadCert succeeded")
	msg := err.Error()

	for _, leak := range []string{cftest.Zone, "suffix7", "AAAA", "PRIVATE KEY", "BEGIN"} {
		assert.NotContains(t, msg, leak)
	}
	keyBody := strings.Join(strings.Split(strings.TrimSpace(keyPEM), "\n")[1:], "")
	for i := 0; i+12 <= len(keyBody); i++ {
		require.NotContains(t, msg, keyBody[i:i+12], "error contains part of the key")
	}
	for _, marker := range []string{"[redacted PEM]", "token=[redacted]", "zone=[redacted]"} {
		assert.Contains(t, msg, marker, "error lacks a redaction marker")
	}
	var apiErr *apiError
	require.ErrorAs(t, err, &apiErr)
	for _, m := range apiErr.messages {
		assert.LessOrEqual(t, len(m), maxMessageBytes, "message bytes")
	}
}

func TestErrorsKeepBenignMessages(t *testing.T) {
	cf := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		cftest.WriteAPIError(w, http.StatusBadRequest, 1400, "missing leaf certificate")
	})
	_, err := cf.uploadCert(context.Background(), "cert", "key")
	assert.ErrorContains(t, err, "(code 1400): missing leaf certificate")
	var apiErr *apiError
	if assert.ErrorAs(t, err, &apiErr) {
		assert.True(t, apiErr.decoded, "err is not a decoded API error: %#v", err)
	}
}

func TestSanitizeOrder(t *testing.T) {
	cf := &cfClient{token: cftest.Token, zoneID: cftest.Zone}
	got := cf.sanitize("Bearer " + cftest.Token + "; zone " + cftest.Zone + "; ok")
	assert.Equal(t, "Bearer [redacted]; zone [redacted]; ok", got, "sanitize")
}

func TestStalledRequest(t *testing.T) {
	received := make(chan struct{})
	cf := newTestClient(t, func(_ http.ResponseWriter, r *http.Request) {
		close(received)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := cf.listCerts(ctx)
		errc <- err
	}()

	select {
	case <-received:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the server did not receive the request")
	}
	cancel()
	select {
	case err := <-errc:
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.NotContains(t, err.Error(), cftest.Zone, "err contains the zone ID")
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the request did not return after its context was cancelled")
	}
}

func TestAPIMessagesTolerateShapes(t *testing.T) {
	var env envelope
	data := `{"success":false,"errors":[{"code":7,"message":"a"},"b",42],"messages":{"odd":true},"result":null}`
	require.NoError(t, json.Unmarshal([]byte(data), &env), "decode")
	if assert.Len(t, env.Errors, 2) {
		assert.Equal(t, 7, env.Errors[0].Code)
		assert.Equal(t, "b", env.Errors[1].Message)
	}
}

// TestZoneCertPathGuards checks that the zone certificate requests refuse
// an ID that could reach another path, before sending anything.
func TestZoneCertPathGuards(t *testing.T) {
	requests := 0
	cf := newTestClient(t, func(http.ResponseWriter, *http.Request) { requests++ })
	ctx := context.Background()
	for _, id := range []string{"settings", "hostnames", "../settings", "", strings.Repeat("a", 31)} {
		_, err := cf.getZoneCert(ctx, id)
		assert.Error(t, err, "getZoneCert(%q)", id)
		assert.Error(t, cf.deleteZoneCert(ctx, id), "deleteZoneCert(%q)", id)
	}
	assert.Zero(t, requests, "requests sent")
}
