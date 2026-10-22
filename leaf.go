package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/krystal/aopctl/aopctl"
)

const (
	defaultTimeout = 10 * time.Minute

	// hostnamesPath is the association endpoint, as the rollback guidance
	// shows it.
	hostnamesPath = "/zones/{zone}/origin_tls_client_auth/hostnames"

	pruneWarning = "aopctl can only check the hostnames you listed. If any other hostname still uses one of these certificates, deleting it breaks AOP for that hostname. Cloudflare's docs say such a delete is refused, but that is unverified."
)

// hostnames returns the --hostname flags, or AOP_HOSTNAMES when no flag is
// given, normalized and deduplicated.
func (a *app) hostnames(flags []string) ([]string, error) {
	entries := flags
	if len(entries) == 0 {
		entries = strings.FieldsFunc(a.getenv("AOP_HOSTNAMES"), func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})
	}
	hosts, err := aopctl.NormalizeHostnames(entries)
	if err != nil {
		return nil, &usageError{msg: err.Error()}
	}
	return hosts, nil
}

// validateCertID keeps a --cert-id from changing the request path.
func validateCertID(id string) error {
	if !aopctl.ValidHostnameCertID(id) {
		return usagef("invalid --cert-id %q: want a Cloudflare certificate ID", id)
	}
	return nil
}

func requireHostnames(hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("no hostnames: set AOP_HOSTNAMES or pass --hostname")
	}
	return nil
}

func hostnameFlags(hosts []string) string {
	var b strings.Builder
	for _, h := range hosts {
		b.WriteString(" --hostname " + h)
	}
	return b.String()
}

func formatEnabled(enabled *bool) string {
	if enabled == nil {
		return "null"
	}
	return fmt.Sprint(*enabled)
}

// otherCANote precedes a printed command for certificates AOP_CA_CERT did
// not sign, which leaf associate and leaf prune refuse.
func otherCANote(ids []string) string {
	return fmt.Sprintf("AOP_CA_CERT did not sign %s, so run the next command with AOP_CA_CERT set to the CA that did. During a CA rotation, that is the old CA.", strings.Join(ids, ", "))
}

// cliError rewrites library errors to name the command's inputs: the
// AOP_CA_* variables, flags and follow-up commands.
func cliError(err error) error {
	if e, ok := errors.AsType[*aopctl.NotSignedError](err); ok {
		return fmt.Errorf("certificate %s is not signed by AOP_CA_CERT", e.CertID)
	}
	if _, ok := errors.AsType[*aopctl.CAExpiryError](err); ok {
		return fmt.Errorf("%w: use a smaller --days or rotate the CA", err)
	}
	if _, ok := errors.AsType[*aopctl.CertificateLimitError](err); ok {
		return fmt.Errorf("%w (see aopctl leaf status and aopctl leaf prune)", err)
	}
	if _, ok := errors.AsType[*aopctl.UploadUnknownError](err); ok {
		return fmt.Errorf("%w, so run aopctl leaf status before retrying", err)
	}
	if errors.Is(err, aopctl.ErrKeyMismatch) {
		return errors.New("AOP_CA_KEY does not match the certificate in AOP_CA_CERT")
	}
	return err
}

// progress prints the library's progress events to stderr.
func (a *app) progress(e aopctl.Event) {
	switch e := e.(type) {
	case aopctl.CertificateUploaded:
		fmt.Fprintf(a.stderr, "Uploaded certificate %s, waiting for it to become active.\n", e.CertID)
	case aopctl.AssociationRequested:
		fmt.Fprintf(a.stderr, "Pointing %d hostnames at %s.\n", len(e.Hostnames), e.CertID)
	case aopctl.CertificateSkipped:
		switch e.Reason {
		case aopctl.SkipAlreadyDeleted:
			fmt.Fprintf(a.stderr, "Already deleted: %s\n", e.CertID)
		case aopctl.SkipNotFound:
			fmt.Fprintf(a.stderr, "Refused %s: not found\n", e.CertID)
		case aopctl.SkipInUse:
			fmt.Fprintf(a.stderr, "Refused %s: still used by %s\n", e.CertID, strings.Join(e.Hostnames, ", "))
		default:
			fmt.Fprintf(a.stderr, "Refused %s: %v\n", e.CertID, cliError(e.Err))
		}
	case aopctl.CertificateRefused:
		fmt.Fprintf(a.stderr, "Refused %s: now used by %s\n", e.CertID, strings.Join(e.Hostnames, ", "))
	case aopctl.CertificateDeleteFailed:
		fmt.Fprintf(a.stderr, "Failed %s: %v\n", e.CertID, e.Err)
	case aopctl.CertificateDeleted:
		fmt.Fprintf(a.stderr, "Deleted %s\n", e.CertID)
	}
}

func (a *app) leafIssue(args []string) error {
	fs := a.flagSet("leaf issue", "[flags]")
	var hostFlags stringList
	fs.Var(&hostFlags, "hostname", "hostname to point at the new leaf (repeatable, replaces AOP_HOSTNAMES)")
	keyType := fs.String("key-type", string(aopctl.KeyTypeECP256), "key type: "+string(aopctl.KeyTypeECP256)+" or "+string(aopctl.KeyTypeRSA3072))
	days := fs.Int("days", 365, "validity in days")
	name := fs.String("name", "aopctl AOP client", "leaf common name")
	dryRun := fs.Bool("dry-run", false, "show the plan without changing anything")
	timeout := fs.Duration("timeout", defaultTimeout, "time budget for the whole command")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := validateKeyType(*keyType); err != nil {
		return err
	}
	if err := validateDays(*days); err != nil {
		return err
	}
	if err := validateTimeout(*timeout); err != nil {
		return err
	}
	hosts, err := a.hostnames(hostFlags)
	if err != nil {
		return err
	}
	if err := requireHostnames(hosts); err != nil {
		return err
	}
	cf, err := a.client()
	if err != nil {
		return err
	}
	caCertPEM, err := a.requireEnv("AOP_CA_CERT")
	if err != nil {
		return err
	}
	caKeyPEM, err := a.requireEnv("AOP_CA_KEY")
	if err != nil {
		return err
	}
	caCert, caKey, err := loadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	plan, err := cf.PlanHostnameIssue(ctx, aopctl.HostnameIssueRequest{
		CACert:     caCert,
		CAKey:      caKey,
		CommonName: *name,
		KeyType:    aopctl.KeyType(*keyType),
		Days:       *days,
		Hostnames:  hosts,
		Progress:   a.progress,
	})
	if err != nil {
		return cliError(err)
	}

	leaf, planHosts, current := plan.Leaf(), plan.Hostnames(), plan.Current()
	fmt.Fprintf(a.stderr, "New leaf:\n  subject:     %s\n  key type:    %s\n  expires:     %s\n  fingerprint: %s\nHostnames:\n",
		leaf.Subject, describeKey(leaf.PublicKey), leaf.NotAfter.UTC().Format(time.RFC3339), aopctl.Fingerprint(leaf))
	for _, h := range planHosts {
		state := "none"
		if assoc := current[h]; assoc != nil {
			state = fmt.Sprintf("%s (enabled=%s)", assoc.CertID, formatEnabled(assoc.Enabled))
		}
		fmt.Fprintf(a.stderr, "  %s: %s -> new\n", h, state)
	}
	if *dryRun {
		fmt.Fprintln(a.stderr, "Dry run: nothing changed.")
		return nil
	}

	result, err := plan.Apply(ctx)
	if rolloutErr, ok := errors.AsType[*aopctl.HostnameRolloutError](err); ok {
		reportRollout(a.stderr, rolloutErr)
		return err
	}
	if err != nil {
		return cliError(err)
	}

	fmt.Fprintf(a.stdout, "The listed hostnames now use certificate %s.\n", result.CertID)
	if len(result.Superseded) == 0 {
		fmt.Fprintln(a.stdout, "The listed hostnames used no other certificate.")
		return nil
	}
	var ownIDs, otherIDs []string
	signed := plan.SignedByCA()
	for _, id := range result.Superseded {
		if signed[id] {
			ownIDs = append(ownIDs, id)
		} else {
			otherIDs = append(otherIDs, id)
		}
	}
	fmt.Fprintf(a.stdout, "They no longer use: %s\n", strings.Join(result.Superseded, ", "))
	fmt.Fprintln(a.stdout, "Delete those soon. Cloudflare's docs leave open which certificate a hostname uses while several exist:")
	if len(ownIDs) > 0 {
		fmt.Fprintf(a.stdout, "  aopctl leaf prune --cert-id %s%s\n", strings.Join(ownIDs, " --cert-id "), hostnameFlags(planHosts))
	}
	if len(otherIDs) > 0 {
		fmt.Fprintf(a.stdout, "  %s\n", otherCANote(otherIDs))
		fmt.Fprintf(a.stdout, "  aopctl leaf prune --cert-id %s%s\n", strings.Join(otherIDs, " --cert-id "), hostnameFlags(planHosts))
	}
	return nil
}

// associationConfig is an entry of the association request body, as the
// rollback guidance shows it.
type associationConfig struct {
	Hostname string `json:"hostname"`
	CertID   string `json:"cert_id"`
	Enabled  *bool  `json:"enabled"`
}

// reportRollout prints how far a failed rollout got and how to resume or
// roll it back.
func reportRollout(w io.Writer, r *aopctl.HostnameRolloutError) {
	fmt.Fprintf(w, "New certificate: %s\nHostnames (original -> observed):\n", r.CertID)
	for _, h := range r.Hostnames {
		observed := "unknown"
		if assoc, ok := r.Observed[h]; ok {
			observed = assoc.String()
		}
		fmt.Fprintf(w, "  %s: %s -> %s\n", h, r.Original[h].String(), observed)
	}
	if !r.AssociateSent {
		// The certificate never became active, so leaf associate would
		// refuse it and there is nothing to roll back.
		fmt.Fprintf(w, "No hostname was changed. If certificate %s becomes active later, point the listed hostnames at it with:\n  aopctl leaf associate --cert-id %s%s\n", r.CertID, r.CertID, hostnameFlags(r.Hostnames))
		fmt.Fprintf(w, "Otherwise, delete it and run aopctl leaf issue again:\n  aopctl leaf prune --cert-id %s%s\n", r.CertID, hostnameFlags(r.Hostnames))
		return
	}
	fmt.Fprintf(w, "To resume, run:\n  aopctl leaf associate --cert-id %s%s\n", r.CertID, hostnameFlags(r.Hostnames))

	var oldIDs, unassociated []string
	byID := map[string][]string{}
	for _, h := range r.Hostnames {
		var id string
		if assoc := r.Original[h]; assoc != nil && assoc.Enabled != nil && *assoc.Enabled {
			id = assoc.CertID
		}
		if id == "" {
			unassociated = append(unassociated, h)
			continue
		}
		if byID[id] == nil {
			oldIDs = append(oldIDs, id)
		}
		byID[id] = append(byID[id], h)
	}
	fmt.Fprintln(w, "To roll back, run:")
	for _, id := range oldIDs {
		if !r.SignedByCA[id] {
			fmt.Fprintf(w, "  %s\n", otherCANote([]string{id}))
		}
		fmt.Fprintf(w, "  aopctl leaf associate --cert-id %s%s\n", id, hostnameFlags(byID[id]))
	}
	if len(unassociated) > 0 {
		config := make([]associationConfig, len(unassociated))
		for i, h := range unassociated {
			config[i] = associationConfig{Hostname: h, CertID: r.CertID}
		}
		body, _ := json.Marshal(map[string][]associationConfig{"config": config})
		fmt.Fprintln(w, "  For hostnames that had no association, void the new one with this API request or in the Cloudflare dashboard. aopctl never voids associations.")
		fmt.Fprintf(w, "  PUT %s\n  %s\n", hostnamesPath, body)
	}
}

func (a *app) leafAssociate(args []string) error {
	fs := a.flagSet("leaf associate", "--cert-id ID [flags]")
	certID := fs.String("cert-id", "", "certificate to point the hostnames at (required)")
	var hostFlags stringList
	fs.Var(&hostFlags, "hostname", "hostname to point at the certificate (repeatable, replaces AOP_HOSTNAMES)")
	dryRun := fs.Bool("dry-run", false, "show the plan without changing anything")
	timeout := fs.Duration("timeout", defaultTimeout, "time budget for the whole command")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if strings.TrimSpace(*certID) == "" {
		return usagef("--cert-id is required")
	}
	if err := validateCertID(*certID); err != nil {
		return err
	}
	if err := validateTimeout(*timeout); err != nil {
		return err
	}
	hosts, err := a.hostnames(hostFlags)
	if err != nil {
		return err
	}
	if err := requireHostnames(hosts); err != nil {
		return err
	}
	cf, err := a.client()
	if err != nil {
		return err
	}
	caCertPEM, err := a.requireEnv("AOP_CA_CERT")
	if err != nil {
		return err
	}
	caCert, err := parseCACert(caCertPEM)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	plan, err := cf.PlanHostnameAssociate(ctx, aopctl.HostnameAssociateRequest{CACert: caCert, CertID: *certID, Hostnames: hosts})
	if err != nil {
		return cliError(err)
	}
	current := plan.Current()
	for _, h := range plan.Hostnames() {
		fmt.Fprintf(a.stderr, "  %s: %s -> %s\n", h, current[h].String(), plan.CertID())
	}
	if *dryRun {
		fmt.Fprintln(a.stderr, "Dry run: nothing changed.")
		return nil
	}

	if err := plan.Apply(ctx); err != nil {
		return cliError(err)
	}
	fmt.Fprintf(a.stdout, "The listed hostnames now use certificate %s.\n", plan.CertID())
	return nil
}

func (a *app) leafStatus(args []string) error {
	fs := a.flagSet("leaf status", "[flags]")
	var hostFlags stringList
	fs.Var(&hostFlags, "hostname", "hostname to report (repeatable, replaces AOP_HOSTNAMES)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	hosts, err := a.hostnames(hostFlags)
	if err != nil {
		return err
	}
	cf, err := a.client()
	if err != nil {
		return err
	}
	var caCert *x509.Certificate
	if v := strings.TrimSpace(a.getenv("AOP_CA_CERT")); v != "" {
		if caCert, err = parseCACert(v); err != nil {
			return err
		}
	}

	report, err := cf.HostnameStatus(context.Background(), aopctl.HostnameStatusRequest{CACert: caCert, Hostnames: hosts})
	if err != nil {
		return err
	}

	now := a.now()
	fmt.Fprintf(a.stdout, "Certificates (%d of %d):\n", len(report.Certificates), aopctl.MaxHostnameCertificates)
	for _, c := range report.Certificates {
		fmt.Fprintf(a.stdout, "  %s\n    status:    %s\n", c.ID, c.Status)
		if c.X509Err != nil {
			fmt.Fprintf(a.stdout, "    certificate: unreadable (%v)\n", c.X509Err)
		} else {
			fmt.Fprintf(a.stdout, "    subject:   %s\n    key type:  %s\n", c.X509.Subject.CommonName, describeKey(c.X509.PublicKey))
			// The fingerprint is what revokedCertFingerprints takes.
			fmt.Fprintf(a.stdout, "    fingerprint: %s\n", aopctl.Fingerprint(c.X509))
		}
		fmt.Fprintf(a.stdout, "    expires:   %s\n", describeExpiry(c.ExpiresOn, c.X509, now))
		signed := "unknown (AOP_CA_CERT not set)"
		if caCert != nil {
			signed = "no"
			if c.SignedByCA {
				signed = "yes"
			}
		}
		fmt.Fprintf(a.stdout, "    signed by AOP_CA_CERT: %s\n", signed)
		using := "none of the listed hostnames"
		if len(c.UsedBy) > 0 {
			using = strings.Join(c.UsedBy, ", ")
		}
		fmt.Fprintf(a.stdout, "    used by:   %s\n", using)
	}
	if len(report.Hostnames) > 0 {
		fmt.Fprintln(a.stdout, "Hostnames:")
		for _, h := range report.Hostnames {
			fmt.Fprintf(a.stdout, "  %s: %s\n", h, report.Associations[h].String())
		}
	}
	fmt.Fprintln(a.stdout, "Associations of hostnames you did not list cannot be discovered through the Cloudflare API.")
	return nil
}

// describeExpiry prefers the certificate's own expiry to Cloudflare's
// expires_on field.
func describeExpiry(expiresOn string, parsed *x509.Certificate, now time.Time) string {
	var notAfter time.Time
	if parsed != nil {
		notAfter = parsed.NotAfter
	} else if t, err := time.Parse(time.RFC3339, expiresOn); err == nil {
		notAfter = t
	} else {
		return expiresOn
	}
	expires := notAfter.UTC().Format(time.RFC3339)
	days := int(math.Floor(notAfter.Sub(now).Hours() / 24))
	if days < 0 {
		return expires + " (expired)"
	}
	return fmt.Sprintf("%s (%d days left)", expires, days)
}

func (a *app) leafPrune(args []string) error {
	fs := a.flagSet("leaf prune", "--cert-id ID... [flags]")
	var idFlags, hostFlags stringList
	fs.Var(&idFlags, "cert-id", "certificate to delete (repeatable, required)")
	fs.Var(&hostFlags, "hostname", "hostname to check before deleting (repeatable, replaces AOP_HOSTNAMES)")
	yes := fs.Bool("yes", false, "delete without asking for confirmation")
	timeout := fs.Duration("timeout", defaultTimeout, "time budget for the whole command")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var ids []string
	seen := map[string]bool{}
	for _, id := range idFlags {
		id = strings.TrimSpace(id)
		if err := validateCertID(id); err != nil {
			return err
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return usagef("--cert-id is required: run aopctl leaf status to find certificates the listed hostnames no longer use")
	}
	if err := validateTimeout(*timeout); err != nil {
		return err
	}
	hosts, err := a.hostnames(hostFlags)
	if err != nil {
		return err
	}
	if err := requireHostnames(hosts); err != nil {
		return err
	}
	cf, err := a.client()
	if err != nil {
		return err
	}
	caCertPEM, err := a.requireEnv("AOP_CA_CERT")
	if err != nil {
		return err
	}
	caCert, err := parseCACert(caCertPEM)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	plan, err := cf.PlanHostnamePrune(ctx, aopctl.HostnamePruneRequest{
		CACert:    caCert,
		CertIDs:   ids,
		Hostnames: hosts,
		Progress:  a.progress,
	})
	if err != nil {
		return cliError(err)
	}
	failed := false
	for _, s := range plan.Skipped() {
		if s.Reason != aopctl.SkipAlreadyDeleted {
			failed = true
		}
	}

	if targets := plan.Targets(); len(targets) > 0 {
		fmt.Fprintln(a.stderr, "Certificates to delete:")
		for _, t := range targets {
			state := t.Status
			if t.PendingDeletion {
				state += ", waiting for the earlier delete to finish"
			}
			fmt.Fprintf(a.stderr, "  %s  %s, expires %s, status %s\n",
				t.ID, t.X509.Subject.CommonName, t.X509.NotAfter.UTC().Format(time.RFC3339), state)
		}
		fmt.Fprintln(a.stderr, pruneWarning)
	}
	if n := plan.Deletes(); n > 0 && !*yes {
		ok, err := a.confirm(fmt.Sprintf("Delete %d certificate(s)? [y/N] ", n))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted: nothing deleted")
		}
	}

	if _, err := plan.Apply(ctx); err != nil {
		if !errors.Is(err, aopctl.ErrNotAllDeleted) {
			return err
		}
		failed = true
	}
	if failed {
		return errors.New("some certificates were not deleted")
	}
	return nil
}

// confirm asks on the controlling terminal. Only "y" or "yes" confirms.
func (a *app) confirm(prompt string) (bool, error) {
	tty, err := a.openTTY()
	if err != nil {
		return false, fmt.Errorf("cannot open the terminal to confirm, pass --yes to skip confirmation: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	line, err := bufio.NewReader(tty).ReadString('\n')
	// EOF before a newline aborts, whatever was typed.
	if errors.Is(err, io.EOF) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
