package cli

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/krystal/aopctl/aopctl"
)

const (
	// zoneSettingsPath is the zone-level AOP setting, as the hints show it.
	zoneSettingsPath = "/zones/{zone}/origin_tls_client_auth/settings"

	zoneDisableHint = "aopctl never turns zone-level AOP off. To turn it off, send this API request or use the Cloudflare dashboard:\n  PUT " + zoneSettingsPath + "\n  {\"enabled\":false}"
)

func newZoneCmd(a *app) *cobra.Command {
	return newGroupCmd("zone", "Manage zone-level AOP certificates and the setting",
		newZoneIssueCmd(a), newZoneEnableCmd(a), newZoneStatusCmd(a), newZonePruneCmd(a))
}

// validateZoneCertID keeps a zone --cert-id from reaching the settings or
// hostnames paths, which share its prefix.
func validateZoneCertID(id string) error {
	if !aopctl.ValidZoneCertID(id) {
		return usagef("invalid --cert-id %q: want a zone certificate ID, a UUID or 32 hex digits", id)
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

type zoneIssueOptions struct {
	keyType string
	days    int
	name    string
	dryRun  bool
	yes     bool
	timeout time.Duration
}

func newZoneIssueCmd(a *app) *cobra.Command {
	o := &zoneIssueOptions{}
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a zone-level leaf and upload it",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.zoneIssue(cmd, o)
		},
	}
	keyTypeFlag(cmd, &o.keyType)
	cmd.Flags().IntVar(&o.days, "days", 365, "validity in days")
	cmd.Flags().StringVar(&o.name, "name", "aopctl AOP client", "leaf common name")
	dryRunFlag(cmd, &o.dryRun, "show the plan without changing anything")
	cmd.Flags().BoolVar(&o.yes, "yes", false, "replace a certificate AOP_CA_CERT did not sign without asking for confirmation")
	timeoutFlag(cmd, &o.timeout)
	return cmd
}

func (a *app) zoneIssue(cmd *cobra.Command, o *zoneIssueOptions) error {
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if err := validateKeyType(o.keyType); err != nil {
		return err
	}
	if err := validateDays(o.days); err != nil {
		return err
	}
	if err := validateTimeout(o.timeout); err != nil {
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

	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()

	plan, err := cf.PlanZoneIssue(ctx, aopctl.ZoneIssueRequest{
		CACert:     caCert,
		CAKey:      caKey,
		CommonName: o.name,
		KeyType:    aopctl.KeyType(o.keyType),
		Days:       o.days,
		Progress:   a.progress(stderr),
	})
	if err != nil {
		return a.cliError(err)
	}

	zone := plan.Zone()
	printLeaf(stderr, plan.Leaf())
	printZoneSummary(stderr, zone)
	replaces := plan.ReplacesOtherCA()
	switch {
	case replaces:
		fmt.Fprintln(stderr, "Warning: AOP_CA_CERT did not sign the certificate in use, or aopctl cannot tell which one that is. Once the new certificate is active, Cloudflare presents it to every origin without a per-hostname certificate, and origins that trust only the other CA reject Cloudflare's requests.")
	case zone.Enabled:
		fmt.Fprintln(stderr, "Once the new certificate is active, Cloudflare presents it to every origin without a per-hostname certificate.")
	default:
		fmt.Fprintf(stderr, "Zone-level AOP is disabled, so Cloudflare does not use the new certificate until you run %s zone enable.\n", a.commandPath())
	}
	if o.dryRun {
		fmt.Fprintln(stderr, "Dry run: nothing changed.")
		return nil
	}
	if replaces && !o.yes {
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
		fmt.Fprintf(stderr, "New certificate %s did not become active.", rolloutErr.CertID)
		if rolloutErr.Enabled {
			fmt.Fprint(stderr, " Zone-level AOP is enabled, so Cloudflare uses it if it becomes active later.")
		}
		fmt.Fprintf(stderr, "\nTo remove it, run:\n  %s zone prune --cert-id %s\n", a.commandPath(), rolloutErr.CertID)
		return err
	}
	if _, ok := errors.AsType[*aopctl.UploadUnknownError](err); ok {
		return fmt.Errorf("%w, so run %s zone status before retrying", err, a.commandPath())
	}
	if err != nil {
		return a.cliError(err)
	}

	if !zone.Enabled {
		fmt.Fprintf(stdout, "Certificate %s is active. Zone-level AOP is disabled, so Cloudflare does not use it yet. To enable it, run:\n  %s zone enable\n", result.CertID, a.commandPath())
		return nil
	}
	fmt.Fprintf(stdout, "Certificate %s is active, and Cloudflare now uses it as the newest active certificate.\n", result.CertID)
	if len(result.Superseded) == 0 {
		fmt.Fprintln(stdout, "No other zone certificate was active.")
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
	fmt.Fprintf(stdout, "Cloudflare no longer uses: %s\n", strings.Join(result.Superseded, ", "))
	fmt.Fprintln(stdout, "Once requests through Cloudflare pass, delete those:")
	if len(ownIDs) > 0 {
		fmt.Fprintf(stdout, "  %s zone prune --cert-id %s\n", a.commandPath(), strings.Join(ownIDs, " --cert-id "))
	}
	if len(otherIDs) > 0 {
		fmt.Fprintf(stdout, "  %s\n", otherCANote(otherIDs))
		fmt.Fprintf(stdout, "  %s zone prune --cert-id %s\n", a.commandPath(), strings.Join(otherIDs, " --cert-id "))
	}
	return nil
}

type zoneEnableOptions struct {
	yes     bool
	dryRun  bool
	timeout time.Duration
}

func newZoneEnableCmd(a *app) *cobra.Command {
	o := &zoneEnableOptions{}
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Turn on zone-level AOP",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.zoneEnable(cmd, o)
		},
	}
	cmd.Flags().BoolVar(&o.yes, "yes", false, "enable without asking for confirmation")
	dryRunFlag(cmd, &o.dryRun, "show the plan without changing anything")
	timeoutFlag(cmd, &o.timeout)
	return cmd
}

func (a *app) zoneEnable(cmd *cobra.Command, o *zoneEnableOptions) error {
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if err := validateTimeout(o.timeout); err != nil {
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

	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()

	plan, err := cf.PlanZoneEnable(ctx, aopctl.ZoneEnableRequest{CACert: caCert})
	if errors.Is(err, aopctl.ErrNoActiveCertificate) {
		return fmt.Errorf("%w: upload one with %s zone issue", err, a.commandPath())
	}
	if err != nil {
		return a.cliError(err)
	}
	zone := plan.Zone()
	if zone.Enabled {
		fmt.Fprintln(stdout, "Zone-level AOP is already enabled. Nothing changed.")
		return nil
	}

	newest, _ := zone.NewestActive()
	printZoneSummary(stderr, zone)
	fmt.Fprintf(stderr, "Once enabled, Cloudflare presents certificate %s, the newest active one, to every origin in the zone without a per-hostname certificate. Origins that do not trust AOP_CA_CERT reject those requests.\n", newest.ID)
	if o.dryRun {
		fmt.Fprintln(stderr, "Dry run: nothing changed.")
		return nil
	}
	if !o.yes {
		ok, err := a.confirm("Enable zone-level AOP? [y/N] ")
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("aborted: nothing changed")
		}
	}

	err = plan.Apply(ctx)
	if _, ok := errors.AsType[*aopctl.EnableUnknownError](err); ok {
		return fmt.Errorf("%w: check it with %s zone status before retrying", err, a.commandPath())
	}
	if err != nil {
		return a.cliError(err)
	}
	fmt.Fprintf(stdout, "Zone-level AOP is enabled, and Cloudflare presents certificate %s.\n%s\n", newest.ID, zoneDisableHint)
	return nil
}

func newZoneStatusCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the zone-level AOP setting and certificates",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.zoneStatus(cmd)
		},
	}
}

func (a *app) zoneStatus(cmd *cobra.Command) error {
	stdout := cmd.OutOrStdout()
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

	report, err := cf.ZoneStatus(cmd.Context(), aopctl.ZoneStatusRequest{CACert: caCert})
	if err != nil {
		return err
	}

	now := a.now()
	inUse, _ := report.InUse()
	active := 0
	fmt.Fprintf(stdout, "Zone-level AOP: %s\n", formatSetting(report.Enabled))
	fmt.Fprintf(stdout, "Certificates (%d):\n", len(report.Certificates))
	for _, c := range report.Certificates {
		marker := ""
		if inUse != nil && c.ID == inUse.ID {
			marker = "  [in use, derived from uploaded_on]"
		}
		if c.Status == "active" {
			active++
		}
		fmt.Fprintf(stdout, "  %s%s\n    status:    %s\n", c.ID, marker, c.Status)
		if c.X509Err != nil {
			fmt.Fprintf(stdout, "    certificate: unreadable (%v)\n", c.X509Err)
		} else {
			fmt.Fprintf(stdout, "    subject:   %s\n    key type:  %s\n", c.X509.Subject.CommonName, describeKey(c.X509.PublicKey))
			fmt.Fprintf(stdout, "    fingerprint: %s\n", aopctl.Fingerprint(c.X509))
		}
		fmt.Fprintf(stdout, "    expires:   %s\n", describeExpiry(c.ExpiresOn, c.X509, now))
		fmt.Fprintf(stdout, "    uploaded:  %s\n", c.UploadedOn)
		fmt.Fprintf(stdout, "    enabled:   %s (Cloudflare's per-certificate field, undocumented)\n", formatEnabled(c.Enabled))
		signed := "unknown (AOP_CA_CERT not set)"
		if caCert != nil {
			signed = yesNo(c.SignedByCA)
		}
		fmt.Fprintf(stdout, "    signed by AOP_CA_CERT: %s\n", signed)
	}
	fmt.Fprintf(stdout, "In use: %s\n", describeInUse(report))
	if active > 1 {
		fmt.Fprintf(stdout, "Warning: %d certificates are active. Cloudflare uses the most recently deployed one, so delete the others with %s zone prune.\n", active, a.commandPath())
	}
	fmt.Fprintf(stdout, "Per-hostname certificates override zone-level ones for their hostnames, so see %s hostname status too.\n", a.commandPath())
	return nil
}

type zonePruneOptions struct {
	certIDs []string
	yes     bool
	dryRun  bool
	timeout time.Duration
}

func newZonePruneCmd(a *app) *cobra.Command {
	o := &zonePruneOptions{}
	cmd := &cobra.Command{
		Use:   "prune --cert-id ID... [flags]",
		Short: "Delete the named zone-level certificates",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.zonePrune(cmd, o)
		},
	}
	cmd.Flags().StringArrayVar(&o.certIDs, "cert-id", nil, "zone certificate to delete (repeatable, required). While zone-level AOP is enabled, naming every active certificate keeps the newest, which may change the certificate in use")
	cmd.Flags().BoolVar(&o.yes, "yes", false, "delete without asking for confirmation")
	dryRunFlag(cmd, &o.dryRun, "show the plan without changing anything, and exit 1 if it refuses or keeps a named certificate")
	timeoutFlag(cmd, &o.timeout)
	return cmd
}

func (a *app) zonePrune(cmd *cobra.Command, o *zonePruneOptions) error {
	stderr := cmd.ErrOrStderr()
	var ids []string
	seen := map[string]bool{}
	for _, id := range o.certIDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if err := validateZoneCertID(id); err != nil {
			return err
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return usagef("--cert-id is required: run %s zone status to find certificates Cloudflare no longer uses", a.commandPath())
	}
	if err := validateTimeout(o.timeout); err != nil {
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

	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()

	plan, err := cf.PlanZonePrune(ctx, aopctl.ZonePruneRequest{CACert: caCert, CertIDs: ids, Progress: a.progress(stderr)})
	if err != nil {
		return a.cliError(err)
	}
	failed := false
	for _, s := range plan.Skipped() {
		if s.Reason != aopctl.SkipAlreadyDeleted {
			failed = true
		}
	}

	inUse, _ := plan.Zone().InUse()
	if targets := plan.Targets(); len(targets) > 0 {
		fmt.Fprintln(stderr, "Certificates to delete:")
		for _, t := range targets {
			state := t.Status
			if t.PendingDeletion {
				state += ", waiting for the earlier delete to finish"
			}
			if inUse != nil && t.ID == inUse.ID {
				state += ", in use (derived)"
			}
			fmt.Fprintf(stderr, "  %s  %s, expires %s, status %s\n",
				t.ID, t.X509.Subject.CommonName, t.X509.NotAfter.UTC().Format(time.RFC3339), state)
		}
		if inUse != nil && slices.ContainsFunc(targets, func(t aopctl.PruneTarget) bool { return t.ID == inUse.ID }) {
			fmt.Fprintf(stderr, "After the deletes, Cloudflare uses: %s\n", describeFallback(plan.InUseAfter()))
		}
		if plan.ReplacesOtherCA() {
			after, ok := plan.InUseAfter()
			switch {
			case !ok:
				fmt.Fprintln(stderr, "Warning: aopctl cannot tell which certificate Cloudflare uses after the deletes. If AOP_CA_CERT did not sign it, origins that trust only AOP_CA_CERT reject Cloudflare's requests.")
			default:
				fmt.Fprintf(stderr, "Warning: after the deletes, Cloudflare uses certificate %s for every origin without a per-hostname certificate. AOP_CA_CERT did not sign it, so origins that trust only AOP_CA_CERT reject Cloudflare's requests.\n", after.ID)
			}
		}
	}
	if o.dryRun {
		fmt.Fprintln(stderr, "Dry run: nothing changed.")
		if failed {
			return errors.New("some certificates would not be deleted")
		}
		return nil
	}
	if n := plan.Deletes(); n > 0 && !o.yes {
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
