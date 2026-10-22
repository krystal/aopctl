// Package cftest is a stateful fake of Cloudflare's hostname AOP API, with
// helpers for tests of the aopctl library and command. It does not import
// the library, so the fake's wire details are checked independently of the
// client's.
package cftest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Token mixes base64 and other characters, so redacting only base64 runs
// would leave "-suffix7" behind.
var Token = strings.Repeat("A", 32) + "-suffix7"

// Zone is the fake's zone ID.
const Zone = "023e105f4ecef8ad9ca31a8372d0c353"

// Certificate and association statuses.
const (
	StatusActive             = "active"
	StatusPendingDeletion    = "pending_deletion"
	StatusDeleted            = "deleted"
	StatusDeploymentTimedOut = "deployment_timed_out"
	StatusDeletionTimedOut   = "deletion_timed_out"
)

// CodeNoAssociation comes with a 404 for a hostname without an association.
const CodeNoAssociation = 1553

// Fake is a stateful fake of Cloudflare's hostname AOP API.
type Fake struct {
	Mu       sync.Mutex
	Certs    []*Cert
	Assocs   map[string]*Assoc
	requests []Request
	uploads  int
	PerPage  int

	// Statuses a certificate or association reports on successive GETs
	// after an upload, delete or PUT. The last one repeats; "gone" makes a
	// certificate disappear.
	UploadStatuses []string
	DeleteStatuses []string
	AssocStatuses  []string

	// Hook runs with Mu held before the default handling. Returning true
	// means it wrote the response.
	Hook func(w http.ResponseWriter, r *http.Request, body []byte) bool
}

// Cert is a hostname certificate in the fake.
type Cert struct {
	ID       string
	PEM      string
	Statuses []string
}

// Assoc is a hostname's association in the fake.
type Assoc struct {
	CertID   string
	Enabled  *bool
	Statuses []string
}

// Request is a request the fake received.
type Request struct {
	Method string
	Path   string
	Query  string
	Body   []byte
}

// New starts a fake that the test's cleanup stops.
func New(t *testing.T) (*Fake, *httptest.Server) {
	t.Helper()
	f := &Fake{
		Assocs:         map[string]*Assoc{},
		PerPage:        50,
		UploadStatuses: []string{"pending_deployment", StatusActive},
		DeleteStatuses: []string{StatusPendingDeletion, "gone"},
		AssocStatuses:  []string{"pending_deployment", StatusActive},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// next returns the current status and advances to the next one.
func next(statuses *[]string) string {
	s := (*statuses)[0]
	if len(*statuses) > 1 {
		*statuses = (*statuses)[1:]
	}
	return s
}

// AddCert adds a certificate, which reports statuses on successive GETs,
// or active.
func (f *Fake) AddCert(id, pem string, statuses ...string) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if len(statuses) == 0 {
		statuses = []string{StatusActive}
	}
	f.Certs = append(f.Certs, &Cert{ID: id, PEM: pem, Statuses: statuses})
}

// SetAssoc sets an active association for host.
func (f *Fake) SetAssoc(host, certID string, enabled *bool) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.Assocs[host] = &Assoc{CertID: certID, Enabled: enabled, Statuses: []string{StatusActive}}
}

// AssocCertID returns the certificate host's association points at, or "".
func (f *Fake) AssocCertID(host string) string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if a := f.Assocs[host]; a != nil {
		return a.CertID
	}
	return ""
}

func (f *Fake) findCert(id string) (int, *Cert) {
	for i, c := range f.Certs {
		if c.ID == id {
			return i, c
		}
	}
	return -1, nil
}

// Recorded returns the requests received so far.
func (f *Fake) Recorded() []Request {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// Count returns how many requests used method on a path ending in suffix.
func (f *Fake) Count(method, suffix string) int {
	n := 0
	for _, r := range f.Recorded() {
		if r.Method == method && strings.HasSuffix(r.Path, suffix) {
			n++
		}
	}
	return n
}

// Writes returns the requests other than GETs.
func (f *Fake) Writes() []Request {
	var writes []Request
	for _, r := range f.Recorded() {
		if r.Method != http.MethodGet {
			writes = append(writes, r)
		}
	}
	return writes
}

// WriteEnvelope writes a Cloudflare envelope, with extra replacing or
// adding top-level fields.
func WriteEnvelope(w http.ResponseWriter, status int, result any, extra map[string]any) {
	env := map[string]any{"success": status < 300, "errors": []any{}, "messages": []any{}, "result": result}
	maps.Copy(env, extra)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

// WriteAPIError writes an unsuccessful envelope with one error.
func WriteAPIError(w http.ResponseWriter, status, code int, msg string) {
	WriteEnvelope(w, status, nil, map[string]any{
		"success": false,
		"errors":  []any{map[string]any{"code": code, "message": msg}},
	})
}

// WriteRaw writes body as is.
func WriteRaw(w http.ResponseWriter, status int, contentType, body string) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// WriteCutOff sends the headers and the start of a JSON body, then closes
// the connection, so reading the body fails with io.ErrUnexpectedEOF.
func WriteCutOff(t *testing.T, w http.ResponseWriter, status int) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", "1000")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"success":true,"result":{"id":"`)
	w.(http.Flusher).Flush()
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("hijack: %v", err)
		return
	}
	_ = conn.Close()
}

// ResetConnection resets the connection before any response is sent.
func ResetConnection(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("hijack: %v", err)
		return
	}
	_ = conn.(*net.TCPConn).SetLinger(0)
	_ = conn.Close()
}

// Stall holds a request until the client gives up on it, so the command's
// budget runs out while the request is in flight.
func Stall(r *http.Request) {
	<-r.Context().Done()
}

func certJSON(c *Cert, status string) map[string]any {
	return map[string]any{
		"id": c.ID, "certificate": c.PEM, "status": status,
		"expires_on": "2030-01-01T00:00:00Z", "signature": "ECDSAWithSHA256",
	}
}

// ServeHTTP records the request, checks the token and routes it.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.requests = append(f.requests, Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: body})

	if r.Header.Get("Authorization") != "Bearer "+Token {
		WriteAPIError(w, http.StatusForbidden, 10000, "Authentication error")
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/zones/"+Zone+"/origin_tls_client_auth/hostnames")
	if !ok {
		WriteAPIError(w, http.StatusNotFound, 7003, "Could not route")
		return
	}
	if f.Hook != nil && f.Hook(w, r, body) {
		return
	}

	switch {
	case rest == "" && r.Method == http.MethodPut:
		f.putAssociations(w, body)
	case rest == "/certificates" && r.Method == http.MethodGet:
		f.list(w, r)
	case rest == "/certificates" && r.Method == http.MethodPost:
		f.Upload(w, body)
	case strings.HasPrefix(rest, "/certificates/"):
		f.cert(w, r.Method, strings.TrimPrefix(rest, "/certificates/"))
	case strings.HasPrefix(rest, "/") && r.Method == http.MethodGet:
		f.association(w, strings.TrimPrefix(rest, "/"))
	default:
		WriteAPIError(w, http.StatusMethodNotAllowed, 10405, "Method not allowed")
	}
}

func (f *Fake) list(w http.ResponseWriter, r *http.Request) {
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	totalPages := (len(f.Certs) + f.PerPage - 1) / f.PerPage
	result := []any{}
	for i := (page - 1) * f.PerPage; i < len(f.Certs) && i < page*f.PerPage; i++ {
		result = append(result, certJSON(f.Certs[i], f.Certs[i].Statuses[0]))
	}
	WriteEnvelope(w, http.StatusOK, result, map[string]any{"result_info": map[string]any{
		"page": page, "per_page": f.PerPage, "total_pages": totalPages, "count": len(result), "total_count": len(f.Certs),
	}})
}

// Upload handles an upload request body, as a POST does. Call it with Mu
// held, as from a Hook.
func (f *Fake) Upload(w http.ResponseWriter, body []byte) {
	var req struct {
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Certificate == "" || req.PrivateKey == "" {
		WriteAPIError(w, http.StatusBadRequest, 1400, "missing leaf certificate")
		return
	}
	f.uploads++
	c := &Cert{
		ID:       fmt.Sprintf("new-%d", f.uploads),
		PEM:      req.Certificate,
		Statuses: append([]string(nil), f.UploadStatuses...),
	}
	f.Certs = append(f.Certs, c)
	WriteEnvelope(w, http.StatusOK, certJSON(c, "initializing"), nil)
}

func (f *Fake) cert(w http.ResponseWriter, method, id string) {
	i, c := f.findCert(id)
	if c == nil {
		WriteAPIError(w, http.StatusNotFound, 1551, "certificate not found")
		return
	}
	switch method {
	case http.MethodGet:
		status := next(&c.Statuses)
		if status == "gone" {
			f.Certs = append(f.Certs[:i], f.Certs[i+1:]...)
			WriteAPIError(w, http.StatusNotFound, 1551, "certificate not found")
			return
		}
		WriteEnvelope(w, http.StatusOK, certJSON(c, status), nil)
	case http.MethodDelete:
		c.Statuses = append([]string(nil), f.DeleteStatuses...)
		WriteEnvelope(w, http.StatusOK, map[string]any{"id": id}, nil)
	default:
		WriteAPIError(w, http.StatusMethodNotAllowed, 10405, "Method not allowed")
	}
}

func (f *Fake) association(w http.ResponseWriter, host string) {
	a := f.Assocs[host]
	if a == nil {
		WriteAPIError(w, http.StatusNotFound, CodeNoAssociation, "Auth origin pull setting for this hostname not found.")
		return
	}
	WriteEnvelope(w, http.StatusOK, map[string]any{
		"hostname": host, "cert_id": a.CertID, "enabled": a.Enabled, "status": next(&a.Statuses),
	}, nil)
}

// ApplyAssociation sets one hostname's association, as a PUT does. Call it
// with Mu held, as from a Hook.
func (f *Fake) ApplyAssociation(host, certID string, enabled *bool) {
	f.Assocs[host] = &Assoc{CertID: certID, Enabled: enabled, Statuses: append([]string(nil), f.AssocStatuses...)}
}

func (f *Fake) putAssociations(w http.ResponseWriter, body []byte) {
	var req struct {
		Config []struct {
			Hostname string `json:"hostname"`
			CertID   string `json:"cert_id"`
			Enabled  *bool  `json:"enabled"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		WriteAPIError(w, http.StatusBadRequest, 1400, "invalid request")
		return
	}
	result := []any{}
	for _, c := range req.Config {
		f.ApplyAssociation(c.Hostname, c.CertID, c.Enabled)
		result = append(result, map[string]any{"hostname": c.Hostname, "cert_id": c.CertID, "enabled": c.Enabled, "status": "pending_deployment"})
	}
	WriteEnvelope(w, http.StatusOK, result, nil)
}

// IssueLeaf returns the PEM of a 30-day EC P-256 client certificate with
// the common name "existing leaf", signed by the CA.
func IssueLeaf(t *testing.T, ca *x509.Certificate, caKey crypto.Signer) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("leaf serial: %v", err)
	}
	notBefore := time.Now().UTC().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "existing leaf"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(0, 0, 30),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// VerifyClientAuth checks that the leaf chains to the CA for client
// authentication at now.
func VerifyClientAuth(leaf, ca *x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// KeyMatches reports whether key is the certificate's private key.
func KeyMatches(cert *x509.Certificate, key crypto.Signer) bool {
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(cert.PublicKey)
}
