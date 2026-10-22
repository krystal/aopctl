package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/krystal/aopctl/aopctl"
)

const (
	// zoneSettingsPath is the zone-level AOP setting, as the hints show it.
	zoneSettingsPath = "/zones/{zone}/origin_tls_client_auth/settings"

	zoneDisableHint = "aopctl never turns zone-level AOP off. To turn it off, send this API request or use the Cloudflare dashboard:\n  PUT " + zoneSettingsPath + "\n  {\"enabled\":false}"
)

// validateZoneCertID keeps a zone --cert-id from reaching the settings or
// hostnames paths, which share its prefix.
func validateZoneCertID(id string) error {
	if !aopctl.ValidZoneCertID(id) {
		return usagef("invalid --cert-id %q: want a zone certificate ID, which is a UUID", id)
	}
	return nil
}

func formatSetting(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

// describeInUse says which certificate Cloudflare uses, as the library
// derives it.
func describeInUse(zone *aopctl.ZoneStatusReport) string {
	if !zone.Enabled {
		return "none, zone-level AOP is disabled"
	}
	inUse, ok := zone.InUse()
	switch {
	case !ok:
		return "unknown, the active certificates' uploaded_on values are missing, unreadable or equal"
	case inUse == nil:
		return "none, no certificate is active"
	}
	return inUse.ID + " (derived: the newest active certificate)"
}

// printZoneSummary prints the setting, one line per certificate and the
// certificate in use.
func printZoneSummary(w io.Writer, zone *aopctl.ZoneStatusReport) {
	fmt.Fprintf(w, "Zone-level AOP: %s\nZone certificates:\n", formatSetting(zone.Enabled))
	if len(zone.Certificates) == 0 {
		fmt.Fprintln(w, "  none")
	}
	for _, c := range zone.Certificates {
		fmt.Fprintf(w, "  %s  status %s, uploaded %s, signed by AOP_CA_CERT: %s\n", c.ID, c.Status, c.UploadedOn, yesNo(c.SignedByCA))
	}
	fmt.Fprintf(w, "In use: %s\n", describeInUse(zone))
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// describeFallback names the certificate Cloudflare uses after a prune.
func describeFallback(after *aopctl.CertificateInfo, ok bool) string {
	switch {
	case !ok:
		return "unknown, the remaining active certificates' uploaded_on values are missing, unreadable or equal"
	case after == nil:
		return "none, no active certificate remains"
	}
	return fmt.Sprintf("%s (derived: the newest remaining active certificate), signed by AOP_CA_CERT: %s", after.ID, yesNo(after.SignedByCA))
}

func printLeaf(w io.Writer, leaf *x509.Certificate) {
	fmt.Fprintf(w, "New leaf:\n  subject:     %s\n  key type:    %s\n  expires:     %s\n  fingerprint: %s\n",
		leaf.Subject, describeKey(leaf.PublicKey), leaf.NotAfter.UTC().Format(time.RFC3339), aopctl.Fingerprint(leaf))
}

func (a *app) zoneIssue(args []string) error {
	fs := a.flagSet("zone issue", "[flags]")
	keyType := fs.String("key-type", string(aopctl.KeyTypeECP256), "key type: "+string(aopctl.KeyTypeECP256)+" or "+string(aopctl.KeyTypeRSA3072))
	days := fs.Int("days", 365, "validity in days")
	name := fs.String("name", "aopctl AOP client", "leaf common name")
	dryRun := fs.Bool("dry-run", false, "show the plan without changing anything")
	yes := fs.Bool("yes", false, "replace a certificate AOP_CA_CERT did not sign without asking for confirmation")
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

	plan, err := cf.PlanZoneIssue(ctx, aopctl.ZoneIssueRequest{
		CACert:     caCert,
		CAKey:      caKey,
		CommonName: *name,
		KeyType:    aopctl.KeyType(*keyType),
		Days:       *days,
		Progress:   a.progress,
	})
	if err != nil {
		return cliError(err)
	}

	zone := plan.Zone()
	printLeaf(a.stderr, plan.Leaf())
	printZoneSummary(a.stderr, zone)
	replaces := plan.ReplacesOtherCA()
	switch {
	case replaces:
		fmt.Fprintln(a.stderr, "Warning: AOP_CA_CERT did not sign the certificate in use, or aopctl cannot tell which one that is. Once the new certificate is active, Cloudflare presents it to every origin without a per-hostname certificate, and origins that trust only the other CA reject Cloudflare's requests.")
	case zone.Enabled:
		fmt.Fprintln(a.stderr, "Once the new certificate is active, Cloudflare presents it to every origin without a per-hostname certificate.")
	default:
		fmt.Fprintln(a.stderr, "Zone-level AOP is disabled, so Cloudflare does not use the new certificate until you run aopctl zone enable.")
	}
	if *dryRun {
		fmt.Fprintln(a.stderr, "Dry run: nothing changed.")
		return nil
	}
	if replaces && !*yes {
		ok, err := a.confirm("Upload the new certificate and let it replace the one in use? [y/N] ")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted: nothing uploaded")
		}
	}

	result, err := plan.Apply(ctx)
	if rolloutErr, ok := errors.AsType[*aopctl.ZoneRolloutError](err); ok {
		fmt.Fprintf(a.stderr, "New certificate %s did not become active.", rolloutErr.CertID)
		if rolloutErr.Enabled {
			fmt.Fprint(a.stderr, " Zone-level AOP is enabled, so Cloudflare uses it if it becomes active later.")
		}
		fmt.Fprintf(a.stderr, "\nTo remove it, run:\n  aopctl zone prune --cert-id %s\n", rolloutErr.CertID)
		return err
	}
	if _, ok := errors.AsType[*aopctl.UploadUnknownError](err); ok {
		return fmt.Errorf("%w, so run aopctl zone status before retrying", err)
	}
	if err != nil {
		return cliError(err)
	}

	if !zone.Enabled {
		fmt.Fprintf(a.stdout, "Certificate %s is active. Zone-level AOP is disabled, so Cloudflare does not use it yet. To enable it, run:\n  aopctl zone enable\n", result.CertID)
		return nil
	}
	fmt.Fprintf(a.stdout, "Certificate %s is active, and Cloudflare now uses it as the newest active certificate.\n", result.CertID)
	if len(result.Superseded) == 0 {
		fmt.Fprintln(a.stdout, "No other zone certificate was active.")
		return nil
	}
	signed := map[string]bool{}
	for _, c := range zone.Certificates {
		signed[c.ID] = c.SignedByCA
	}
	var ownIDs, otherIDs []string
	for _, id := range result.Superseded {
		if signed[id] {
			ownIDs = append(ownIDs, id)
		} else {
			otherIDs = append(otherIDs, id)
		}
	}
	fmt.Fprintf(a.stdout, "Cloudflare no longer uses: %s\n", strings.Join(result.Superseded, ", "))
	fmt.Fprintln(a.stdout, "Once requests through Cloudflare pass, delete those:")
	if len(ownIDs) > 0 {
		fmt.Fprintf(a.stdout, "  aopctl zone prune --cert-id %s\n", strings.Join(ownIDs, " --cert-id "))
	}
	if len(otherIDs) > 0 {
		fmt.Fprintf(a.stdout, "  %s\n", otherCANote(otherIDs))
		fmt.Fprintf(a.stdout, "  aopctl zone prune --cert-id %s\n", strings.Join(otherIDs, " --cert-id "))
	}
	return nil
}

func (a *app) zoneEnable(args []string) error {
	fs := a.flagSet("zone enable", "[flags]")
	yes := fs.Bool("yes", false, "enable without asking for confirmation")
	dryRun := fs.Bool("dry-run", false, "show the plan without changing anything")
	timeout := fs.Duration("timeout", defaultTimeout, "time budget for the whole command")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := validateTimeout(*timeout); err != nil {
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

	plan, err := cf.PlanZoneEnable(ctx, aopctl.ZoneEnableRequest{CACert: caCert})
	if errors.Is(err, aopctl.ErrNoActiveCertificate) {
		return fmt.Errorf("%w: upload one with aopctl zone issue", err)
	}
	if err != nil {
		return cliError(err)
	}
	zone := plan.Zone()
	if zone.Enabled {
		fmt.Fprintln(a.stdout, "Zone-level AOP is already enabled. Nothing changed.")
		return nil
	}

	newest, _ := zone.NewestActive()
	printZoneSummary(a.stderr, zone)
	fmt.Fprintf(a.stderr, "Once enabled, Cloudflare presents certificate %s, the newest active one, to every origin in the zone without a per-hostname certificate. Origins that do not trust AOP_CA_CERT reject those requests.\n", newest.ID)
	if *dryRun {
		fmt.Fprintln(a.stderr, "Dry run: nothing changed.")
		return nil
	}
	if !*yes {
		ok, err := a.confirm("Enable zone-level AOP? [y/N] ")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted: nothing changed")
		}
	}

	if err := plan.Apply(ctx); err != nil {
		return cliError(err)
	}
	fmt.Fprintf(a.stdout, "Zone-level AOP is enabled, and Cloudflare presents certificate %s.\n%s\n", newest.ID, zoneDisableHint)
	return nil
}

func (a *app) zoneStatus(args []string) error {
	fs := a.flagSet("zone status", "[flags]")
	if err := parseFlags(fs, args); err != nil {
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

	report, err := cf.ZoneStatus(context.Background(), aopctl.ZoneStatusRequest{CACert: caCert})
	if err != nil {
		return err
	}

	now := a.now()
	inUse, _ := report.InUse()
	active := 0
	fmt.Fprintf(a.stdout, "Zone-level AOP: %s\n", formatSetting(report.Enabled))
	fmt.Fprintf(a.stdout, "Certificates (%d):\n", len(report.Certificates))
	for _, c := range report.Certificates {
		marker := ""
		if inUse != nil && c.ID == inUse.ID {
			marker = "  [in use, derived from uploaded_on]"
		}
		if c.Status == "active" {
			active++
		}
		fmt.Fprintf(a.stdout, "  %s%s\n    status:    %s\n", c.ID, marker, c.Status)
		if c.X509Err != nil {
			fmt.Fprintf(a.stdout, "    certificate: unreadable (%v)\n", c.X509Err)
		} else {
			fmt.Fprintf(a.stdout, "    subject:   %s\n    key type:  %s\n", c.X509.Subject.CommonName, describeKey(c.X509.PublicKey))
			fmt.Fprintf(a.stdout, "    fingerprint: %s\n", aopctl.Fingerprint(c.X509))
		}
		fmt.Fprintf(a.stdout, "    expires:   %s\n", describeExpiry(c.ExpiresOn, c.X509, now))
		fmt.Fprintf(a.stdout, "    uploaded:  %s\n", c.UploadedOn)
		fmt.Fprintf(a.stdout, "    enabled:   %s (Cloudflare's per-certificate field, undocumented)\n", formatEnabled(c.Enabled))
		signed := "unknown (AOP_CA_CERT not set)"
		if caCert != nil {
			signed = yesNo(c.SignedByCA)
		}
		fmt.Fprintf(a.stdout, "    signed by AOP_CA_CERT: %s\n", signed)
	}
	fmt.Fprintf(a.stdout, "In use: %s\n", describeInUse(report))
	if active > 1 {
		fmt.Fprintf(a.stdout, "Warning: %d certificates are active. Cloudflare uses the most recently deployed one, so delete the others with aopctl zone prune.\n", active)
	}
	fmt.Fprintln(a.stdout, "Per-hostname certificates override zone-level ones for their hostnames, so see aopctl hostname status too.")
	return nil
}

func (a *app) zonePrune(args []string) error {
	fs := a.flagSet("zone prune", "--cert-id ID... [flags]")
	var idFlags stringList
	fs.Var(&idFlags, "cert-id", "zone certificate to delete (repeatable, required)")
	yes := fs.Bool("yes", false, "delete without asking for confirmation")
	dryRun := fs.Bool("dry-run", false, "show the plan without changing anything")
	timeout := fs.Duration("timeout", defaultTimeout, "time budget for the whole command")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var ids []string
	seen := map[string]bool{}
	for _, id := range idFlags {
		id = strings.TrimSpace(id)
		if err := validateZoneCertID(id); err != nil {
			return err
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return usagef("--cert-id is required: run aopctl zone status to find certificates Cloudflare no longer uses")
	}
	if err := validateTimeout(*timeout); err != nil {
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

	plan, err := cf.PlanZonePrune(ctx, aopctl.ZonePruneRequest{CACert: caCert, CertIDs: ids, Progress: a.progress})
	if err != nil {
		return cliError(err)
	}
	failed := false
	for _, s := range plan.Skipped() {
		if s.Reason != aopctl.SkipAlreadyDeleted {
			failed = true
		}
	}

	inUse, _ := plan.Zone().InUse()
	if targets := plan.Targets(); len(targets) > 0 {
		fmt.Fprintln(a.stderr, "Certificates to delete:")
		for _, t := range targets {
			state := t.Status
			if t.PendingDeletion {
				state += ", waiting for the earlier delete to finish"
			}
			if inUse != nil && t.ID == inUse.ID {
				state += ", in use (derived)"
			}
			fmt.Fprintf(a.stderr, "  %s  %s, expires %s, status %s\n",
				t.ID, t.X509.Subject.CommonName, t.X509.NotAfter.UTC().Format(time.RFC3339), state)
		}
		if inUse != nil && slices.ContainsFunc(targets, func(t aopctl.PruneTarget) bool { return t.ID == inUse.ID }) {
			fmt.Fprintf(a.stderr, "After the deletes, Cloudflare uses: %s\n", describeFallback(plan.InUseAfter()))
		}
		if plan.ReplacesOtherCA() {
			after, ok := plan.InUseAfter()
			switch {
			case !ok:
				fmt.Fprintln(a.stderr, "Warning: aopctl cannot tell which certificate Cloudflare uses after the deletes. If AOP_CA_CERT did not sign it, origins that trust only AOP_CA_CERT reject Cloudflare's requests.")
			default:
				fmt.Fprintf(a.stderr, "Warning: after the deletes, Cloudflare uses certificate %s for every origin without a per-hostname certificate. AOP_CA_CERT did not sign it, so origins that trust only AOP_CA_CERT reject Cloudflare's requests.\n", after.ID)
			}
		}
	}
	if *dryRun {
		fmt.Fprintln(a.stderr, "Dry run: nothing changed.")
		if failed {
			return errors.New("some certificates would not be deleted")
		}
		return nil
	}
	if n := plan.Deletes(); n > 0 && !*yes {
		ok, err := a.confirm(fmt.Sprintf("Delete %d zone certificate(s)? [y/N] ", n))
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
