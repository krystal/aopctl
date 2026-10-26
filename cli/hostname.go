package cli

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

	"github.com/spf13/cobra"

	"github.com/krystal/aopctl/aopctl"
)

const (
	defaultTimeout = 10 * time.Minute

	// hostnamesPath is the association endpoint, as the rollback guidance
	// shows it.
	hostnamesPath = "/zones/{zone}/origin_tls_client_auth/hostnames"

	pruneWarning = "aopctl can only check the hostnames you listed. If any other hostname still uses one of these certificates, deleting it breaks AOP for that hostname. Cloudflare's docs say such a delete is refused, but that is unverified."
)

func newHostnameCmd(a *app) *cobra.Command {
	return newGroupCmd("hostname", "Manage per-hostname AOP certificates",
		newHostnameIssueCmd(a), newHostnameAssociateCmd(a), newHostnameStatusCmd(a), newHostnamePruneCmd(a))
}

// hostnameFlag adds --hostname, which takes comma-separated lists and
// completes from the configured hostnames.
func (a *app) hostnameFlag(cmd *cobra.Command, p *[]string, usage string) {
	cmd.Flags().StringSliceVar(p, "hostname", nil, usage)
	_ = cmd.RegisterFlagCompletionFunc("hostname", a.completeHostnames)
}

// completeHostnames offers the configured hostnames. It never calls the
// API or reads a secret, so completion needs no token.
func (a *app) completeHostnames(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
	hosts, err := a.configuredHostnames()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return hosts, cobra.ShellCompDirectiveNoFileComp
}

// hostnames returns the --hostname flags, or the configured hostnames when
// no flag is given, normalized and deduplicated. flags is nil only when no
// flag is given: --hostname "" sets it to an empty list, which must not
// fall back to the configured hostnames. It reads the config for cmd, which
// prints the config file's warnings first.
func (a *app) hostnames(cmd *cobra.Command, flags []string) ([]string, error) {
	if _, err := a.commandConfig(cmd); err != nil {
		return nil, err
	}
	entries := flags
	if entries == nil {
		var err error
		if entries, err = a.configuredHostnames(); err != nil {
			return nil, err
		}
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

func (a *app) requireHostnames(hosts []string) error {
	if len(hosts) > 0 {
		return nil
	}
	if c, err := a.config(); err == nil && c.file != nil {
		return fmt.Errorf("no hostnames: set %s in %s or pass --hostname", settingHostnames.key, c.where())
	}
	return fmt.Errorf("no hostnames: set %s or pass --hostname", settingHostnames.env)
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

// otherCANote precedes a printed command for certificates the configured
// CA did not sign, which hostname associate and hostname prune refuse.
func (a *app) otherCANote(ids []string) string {
	ca := a.name(settingCACert)
	return fmt.Sprintf("%s did not sign %s, so run the next command with %s set to the CA that did. During a CA rotation, that is the old CA.", ca, strings.Join(ids, ", "), ca)
}

// cliError rewrites library errors to name the command's inputs: the CA
// settings, flags and follow-up commands in the zone.
func (a *app) cliError(err error, zoneID string) error {
	if e, ok := errors.AsType[*aopctl.NotSignedError](err); ok {
		return fmt.Errorf("certificate %s is not signed by %s", e.CertID, a.name(settingCACert))
	}
	if _, ok := errors.AsType[*aopctl.CAExpiryError](err); ok {
		return fmt.Errorf("%w: use a smaller --days or rotate the CA", err)
	}
	if _, ok := errors.AsType[*aopctl.CertificateLimitError](err); ok {
		return fmt.Errorf("%w (see %s and %s)", err, a.zoneCmd(zoneID, "hostname status"), a.zoneCmd(zoneID, "hostname prune"))
	}
	if _, ok := errors.AsType[*aopctl.UploadUnknownError](err); ok {
		return fmt.Errorf("%w, so run %s before retrying", err, a.zoneCmd(zoneID, "hostname status"))
	}
	if errors.Is(err, aopctl.ErrKeyMismatch) {
		return a.keyMismatchError()
	}
	return err
}

// progress returns a callback that prints the library's progress events in
// the zone to w.
func (a *app) progress(w io.Writer, zoneID string) func(aopctl.Event) {
	return func(e aopctl.Event) {
		switch e := e.(type) {
		case aopctl.CertificateUploaded:
			fmt.Fprintf(w, "Uploaded certificate %s, waiting for it to become active.\n", e.CertID)
		case aopctl.AssociationRequested:
			fmt.Fprintf(w, "Pointing %d hostnames at %s.\n", len(e.Hostnames), e.CertID)
		case aopctl.CertificateSkipped:
			switch e.Reason {
			case aopctl.SkipAlreadyDeleted:
				fmt.Fprintf(w, "Already deleted: %s\n", e.CertID)
			case aopctl.SkipNotFound:
				fmt.Fprintf(w, "Refused %s: not found\n", e.CertID)
			case aopctl.SkipInUse:
				fmt.Fprintf(w, "Refused %s: still used by %s\n", e.CertID, strings.Join(e.Hostnames, ", "))
			case aopctl.SkipLastActive:
				fmt.Fprintf(w, "Refused %s: it is the last active zone certificate and zone-level AOP is enabled. Upload a replacement with %s first.\n", e.CertID, a.zoneCmd(zoneID, "zone issue"))
			default:
				fmt.Fprintf(w, "Refused %s: %v\n", e.CertID, a.cliError(e.Err, zoneID))
			}
		case aopctl.CertificateRefused:
			if e.Reason == aopctl.SkipLastActive {
				fmt.Fprintf(w, "Refused %s: it is now the last active zone certificate and zone-level AOP is enabled\n", e.CertID)
				break
			}
			fmt.Fprintf(w, "Refused %s: now used by %s\n", e.CertID, strings.Join(e.Hostnames, ", "))
		case aopctl.CertificateDeleteFailed:
			fmt.Fprintf(w, "Failed %s: %v\n", e.CertID, e.Err)
		case aopctl.CertificateDeleted:
			fmt.Fprintf(w, "Deleted %s\n", e.CertID)
		}
	}
}

type hostnameIssueOptions struct {
	zone      string
	hostnames []string
	keyType   string
	days      int
	name      string
	dryRun    bool
	timeout   time.Duration
}

func newHostnameIssueCmd(a *app) *cobra.Command {
	o := &hostnameIssueOptions{}
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a leaf, upload it and point the hostnames at it",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.hostnameIssue(cmd, o)
		},
	}
	zoneFlag(cmd, &o.zone, hostnameZoneUsage)
	a.hostnameFlag(cmd, &o.hostnames, "hostnames to point at the new leaf (repeatable or comma-separated, replaces the configured hostnames)")
	keyTypeFlag(cmd, &o.keyType)
	cmd.Flags().IntVar(&o.days, "days", 365, "validity in days")
	cmd.Flags().StringVar(&o.name, "name", "aopctl AOP client", "leaf common name")
	dryRunFlag(cmd, &o.dryRun, "show the plan without changing anything")
	timeoutFlag(cmd, &o.timeout)
	return cmd
}

func (a *app) hostnameIssue(cmd *cobra.Command, o *hostnameIssueOptions) error {
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
	zone, err := parseZoneArg(o.zone)
	if err != nil {
		return err
	}
	hosts, err := a.hostnames(cmd, o.hostnames)
	if err != nil {
		return err
	}
	if err := a.requireHostnames(hosts); err != nil {
		return err
	}
	token, err := a.require(cmd, settingToken)
	if err != nil {
		return err
	}
	caCertPEM, err := a.require(cmd, settingCACert)
	if err != nil {
		return err
	}
	caKeyPEM, err := a.require(cmd, settingCAKey)
	if err != nil {
		return err
	}
	caCert, caKey, err := a.loadCA(caCertPEM, caKeyPEM)
	if err != nil {
		return err
	}
	zoneID, err := a.configuredZone(cmd, zone)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()

	zones, err := a.hostnameZones(ctx, token, zone, zoneID, hosts, o.hostnames != nil)
	if err != nil {
		return err
	}
	target, err := a.writeZone("hostname issue", zones)
	if err != nil {
		return err
	}
	zoneID = target.zone.ID
	cf, err := a.newClient(token, zoneID)
	if err != nil {
		return err
	}
	printZone(stderr, target.zone)
	plan, err := cf.PlanHostnameIssue(ctx, aopctl.HostnameIssueRequest{
		CACert:     caCert,
		CAKey:      caKey,
		CommonName: o.name,
		KeyType:    aopctl.KeyType(o.keyType),
		Days:       o.days,
		Hostnames:  target.hosts,
		Progress:   a.progress(stderr, zoneID),
	})
	if err != nil {
		return a.cliError(err, zoneID)
	}

	leaf, planHosts, current := plan.Leaf(), plan.Hostnames(), plan.Current()
	printLeaf(stderr, leaf)
	fmt.Fprintln(stderr, "Hostnames:")
	for _, h := range planHosts {
		state := "none"
		if assoc := current[h]; assoc != nil {
			state = fmt.Sprintf("%s (enabled=%s)", assoc.CertID, formatEnabled(assoc.Enabled))
		}
		fmt.Fprintf(stderr, "  %s: %s -> new\n", h, state)
	}
	if o.dryRun {
		fmt.Fprintln(stderr, "Dry run: nothing changed.")
		return nil
	}

	result, err := plan.Apply(ctx)
	if rolloutErr, ok := errors.AsType[*aopctl.HostnameRolloutError](err); ok {
		a.reportRollout(stderr, rolloutErr, zoneID)
		return err
	}
	if err != nil {
		return a.cliError(err, zoneID)
	}

	fmt.Fprintf(stdout, "The listed hostnames now use certificate %s.\n", result.CertID)
	if len(result.Superseded) == 0 {
		fmt.Fprintln(stdout, "The listed hostnames used no other certificate.")
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
	fmt.Fprintf(stdout, "They no longer use: %s\n", strings.Join(result.Superseded, ", "))
	fmt.Fprintln(stdout, "Delete those soon. Cloudflare's docs leave open which certificate a hostname uses while several exist:")
	if len(ownIDs) > 0 {
		fmt.Fprintf(stdout, "  %s --cert-id %s%s\n", a.zoneCmd(zoneID, "hostname prune"), strings.Join(ownIDs, " --cert-id "), hostnameFlags(planHosts))
	}
	if len(otherIDs) > 0 {
		fmt.Fprintf(stdout, "  %s\n", a.otherCANote(otherIDs))
		fmt.Fprintf(stdout, "  %s --cert-id %s%s\n", a.zoneCmd(zoneID, "hostname prune"), strings.Join(otherIDs, " --cert-id "), hostnameFlags(planHosts))
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

// reportRollout prints how far a failed rollout in the zone got and how to
// resume or roll it back.
func (a *app) reportRollout(w io.Writer, r *aopctl.HostnameRolloutError, zoneID string) {
	associate, prune := a.zoneCmd(zoneID, "hostname associate"), a.zoneCmd(zoneID, "hostname prune")
	fmt.Fprintf(w, "New certificate: %s\nHostnames (original -> observed):\n", r.CertID)
	for _, h := range r.Hostnames {
		observed := "unknown"
		if assoc, ok := r.Observed[h]; ok {
			observed = assoc.String()
		}
		fmt.Fprintf(w, "  %s: %s -> %s\n", h, r.Original[h].String(), observed)
	}
	if !r.AssociateSent {
		// The certificate never became active, so hostname associate would
		// refuse it and there is nothing to roll back.
		fmt.Fprintf(w, "No hostname was changed. If certificate %s becomes active later, point the listed hostnames at it with:\n  %s --cert-id %s%s\n", r.CertID, associate, r.CertID, hostnameFlags(r.Hostnames))
		fmt.Fprintf(w, "Otherwise, delete it and run %s again:\n  %s --cert-id %s%s\n", a.zoneCmd(zoneID, "hostname issue"), prune, r.CertID, hostnameFlags(r.Hostnames))
		return
	}
	fmt.Fprintf(w, "To resume, run:\n  %s --cert-id %s%s\n", associate, r.CertID, hostnameFlags(r.Hostnames))

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
			fmt.Fprintf(w, "  %s\n", a.otherCANote([]string{id}))
		}
		fmt.Fprintf(w, "  %s --cert-id %s%s\n", associate, id, hostnameFlags(byID[id]))
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

type hostnameAssociateOptions struct {
	certID    string
	zone      string
	hostnames []string
	dryRun    bool
	timeout   time.Duration
}

func newHostnameAssociateCmd(a *app) *cobra.Command {
	o := &hostnameAssociateOptions{}
	cmd := &cobra.Command{
		Use:   "associate --cert-id ID [flags]",
		Short: "Point the hostnames at an existing leaf",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.hostnameAssociate(cmd, o)
		},
	}
	cmd.Flags().StringVar(&o.certID, "cert-id", "", "certificate to point the hostnames at (required)")
	zoneFlag(cmd, &o.zone, hostnameZoneUsage)
	a.hostnameFlag(cmd, &o.hostnames, "hostnames to point at the certificate (repeatable or comma-separated, replaces the configured hostnames)")
	dryRunFlag(cmd, &o.dryRun, "show the plan without changing anything")
	timeoutFlag(cmd, &o.timeout)
	return cmd
}

func (a *app) hostnameAssociate(cmd *cobra.Command, o *hostnameAssociateOptions) error {
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if strings.TrimSpace(o.certID) == "" {
		return usagef("--cert-id is required")
	}
	if err := validateCertID(o.certID); err != nil {
		return err
	}
	if err := validateTimeout(o.timeout); err != nil {
		return err
	}
	zone, err := parseZoneArg(o.zone)
	if err != nil {
		return err
	}
	hosts, err := a.hostnames(cmd, o.hostnames)
	if err != nil {
		return err
	}
	if err := a.requireHostnames(hosts); err != nil {
		return err
	}
	token, err := a.require(cmd, settingToken)
	if err != nil {
		return err
	}
	caCertPEM, err := a.require(cmd, settingCACert)
	if err != nil {
		return err
	}
	caCert, err := a.parseCACert(caCertPEM)
	if err != nil {
		return err
	}
	zoneID, err := a.configuredZone(cmd, zone)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()

	zones, err := a.hostnameZones(ctx, token, zone, zoneID, hosts, o.hostnames != nil)
	if err != nil {
		return err
	}
	target, err := a.writeZone("hostname associate", zones)
	if err != nil {
		return err
	}
	cf, err := a.newClient(token, target.zone.ID)
	if err != nil {
		return err
	}
	printZone(stderr, target.zone)
	plan, err := cf.PlanHostnameAssociate(ctx, aopctl.HostnameAssociateRequest{CACert: caCert, CertID: o.certID, Hostnames: target.hosts})
	if err != nil {
		return a.cliError(err, target.zone.ID)
	}
	current := plan.Current()
	for _, h := range plan.Hostnames() {
		fmt.Fprintf(stderr, "  %s: %s -> %s\n", h, current[h].String(), plan.CertID())
	}
	if o.dryRun {
		fmt.Fprintln(stderr, "Dry run: nothing changed.")
		return nil
	}

	if err := plan.Apply(ctx); err != nil {
		return a.cliError(err, target.zone.ID)
	}
	fmt.Fprintf(stdout, "The listed hostnames now use certificate %s.\n", plan.CertID())
	return nil
}

type hostnameStatusOptions struct {
	zone      string
	hostnames []string
}

func newHostnameStatusCmd(a *app) *cobra.Command {
	o := &hostnameStatusOptions{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "List leaf certificates and hostname associations",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.hostnameStatus(cmd, o)
		},
	}
	zoneFlag(cmd, &o.zone, hostnameZoneUsage)
	a.hostnameFlag(cmd, &o.hostnames, "hostnames to report (repeatable or comma-separated, replaces the configured hostnames)")
	return cmd
}

func (a *app) hostnameStatus(cmd *cobra.Command, o *hostnameStatusOptions) error {
	stdout := cmd.OutOrStdout()
	zone, err := parseZoneArg(o.zone)
	if err != nil {
		return err
	}
	hosts, err := a.hostnames(cmd, o.hostnames)
	if err != nil {
		return err
	}
	token, err := a.require(cmd, settingToken)
	if err != nil {
		return err
	}
	var caCert *x509.Certificate
	caCertPEM, err := a.lookup(cmd, settingCACert)
	if err != nil {
		return err
	}
	if caCertPEM != "" {
		if caCert, err = a.parseCACert(caCertPEM); err != nil {
			return err
		}
	}
	zoneID, err := a.configuredZone(cmd, zone)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	zones, err := a.hostnameZones(ctx, token, zone, zoneID, hosts, o.hostnames != nil)
	if err != nil {
		return err
	}
	// Read every zone before printing, so a failure prints no partial
	// report.
	reports := make([]*aopctl.HostnameStatusReport, len(zones))
	for i, z := range zones {
		cf, err := a.newClient(token, z.zone.ID)
		if err != nil {
			return err
		}
		reports[i], err = cf.HostnameStatus(ctx, aopctl.HostnameStatusRequest{CACert: caCert, Hostnames: z.hosts})
		if err != nil {
			if z.zone.Name != "" {
				err = fmt.Errorf("zone %s: %w", z.zone.Name, err)
			}
			return err
		}
	}

	now := a.now()
	for i, z := range zones {
		if i > 0 {
			fmt.Fprintln(stdout)
		}
		printZone(stdout, z.zone)
		printHostnameReport(stdout, reports[i], caCert, a.name(settingCACert), now)
	}
	fmt.Fprintln(stdout, "Associations of hostnames you did not list cannot be discovered through the Cloudflare API.")
	return nil
}

// printHostnameReport prints one zone's hostname certificates and the
// listed hostnames' associations. caName names the CA certificate setting.
func printHostnameReport(stdout io.Writer, report *aopctl.HostnameStatusReport, caCert *x509.Certificate, caName string, now time.Time) {
	fmt.Fprintf(stdout, "Certificates (%d of %d):\n", len(report.Certificates), aopctl.MaxHostnameCertificates)
	for _, c := range report.Certificates {
		fmt.Fprintf(stdout, "  %s\n    status:    %s\n", c.ID, c.Status)
		if c.X509Err != nil {
			fmt.Fprintf(stdout, "    certificate: unreadable (%v)\n", c.X509Err)
		} else {
			fmt.Fprintf(stdout, "    subject:   %s\n    key type:  %s\n", c.X509.Subject.CommonName, describeKey(c.X509.PublicKey))
			// The fingerprint is what revokedCertFingerprints takes.
			fmt.Fprintf(stdout, "    fingerprint: %s\n", aopctl.Fingerprint(c.X509))
		}
		fmt.Fprintf(stdout, "    expires:   %s\n", describeExpiry(c.ExpiresOn, c.X509, now))
		signed := "unknown (" + caName + " not set)"
		if caCert != nil {
			signed = "no"
			if c.SignedByCA {
				signed = "yes"
			}
		}
		fmt.Fprintf(stdout, "    signed by %s: %s\n", caName, signed)
		using := "none of the listed hostnames"
		if len(c.UsedBy) > 0 {
			using = strings.Join(c.UsedBy, ", ")
		}
		fmt.Fprintf(stdout, "    used by:   %s\n", using)
	}
	if len(report.Hostnames) > 0 {
		fmt.Fprintln(stdout, "Hostnames:")
		for _, h := range report.Hostnames {
			fmt.Fprintf(stdout, "  %s: %s\n", h, report.Associations[h].String())
		}
	}
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

type hostnamePruneOptions struct {
	certIDs   []string
	zone      string
	hostnames []string
	yes       bool
	timeout   time.Duration
}

func newHostnamePruneCmd(a *app) *cobra.Command {
	o := &hostnamePruneOptions{}
	cmd := &cobra.Command{
		Use:   "prune --cert-id ID... [flags]",
		Short: "Delete the named leaf certificates",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.hostnamePrune(cmd, o)
		},
	}
	cmd.Flags().StringArrayVar(&o.certIDs, "cert-id", nil, "certificate to delete (repeatable, required)")
	zoneFlag(cmd, &o.zone, hostnameZoneUsage)
	a.hostnameFlag(cmd, &o.hostnames, "hostnames to check before deleting (repeatable or comma-separated, replaces the configured hostnames)")
	cmd.Flags().BoolVar(&o.yes, "yes", false, "delete without asking for confirmation")
	timeoutFlag(cmd, &o.timeout)
	return cmd
}

func (a *app) hostnamePrune(cmd *cobra.Command, o *hostnamePruneOptions) error {
	stderr := cmd.ErrOrStderr()
	zone, err := parseZoneArg(o.zone)
	if err != nil {
		return err
	}
	var ids []string
	seen := map[string]bool{}
	for _, id := range o.certIDs {
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
		return usagef("--cert-id is required: run %s hostname status%s to find certificates the listed hostnames no longer use", a.commandPath(), a.zoneHint(zone))
	}
	if err := validateTimeout(o.timeout); err != nil {
		return err
	}
	hosts, err := a.hostnames(cmd, o.hostnames)
	if err != nil {
		return err
	}
	if err := a.requireHostnames(hosts); err != nil {
		return err
	}
	token, err := a.require(cmd, settingToken)
	if err != nil {
		return err
	}
	caCertPEM, err := a.require(cmd, settingCACert)
	if err != nil {
		return err
	}
	caCert, err := a.parseCACert(caCertPEM)
	if err != nil {
		return err
	}
	zoneID, err := a.configuredZone(cmd, zone)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()

	zones, err := a.hostnameZones(ctx, token, zone, zoneID, hosts, o.hostnames != nil)
	if err != nil {
		return err
	}
	target, err := a.writeZone("hostname prune", zones)
	if err != nil {
		return err
	}
	zoneID = target.zone.ID
	cf, err := a.newClient(token, zoneID)
	if err != nil {
		return err
	}
	printZone(stderr, target.zone)
	plan, err := cf.PlanHostnamePrune(ctx, aopctl.HostnamePruneRequest{
		CACert:    caCert,
		CertIDs:   ids,
		Hostnames: target.hosts,
		Progress:  a.progress(stderr, zoneID),
	})
	if err != nil {
		return a.cliError(err, zoneID)
	}
	failed := false
	for _, s := range plan.Skipped() {
		if s.Reason != aopctl.SkipAlreadyDeleted {
			failed = true
		}
	}

	if targets := plan.Targets(); len(targets) > 0 {
		fmt.Fprintln(stderr, "Certificates to delete:")
		for _, t := range targets {
			state := t.Status
			if t.PendingDeletion {
				state += ", waiting for the earlier delete to finish"
			}
			fmt.Fprintf(stderr, "  %s  %s, expires %s, status %s\n",
				t.ID, t.X509.Subject.CommonName, t.X509.NotAfter.UTC().Format(time.RFC3339), state)
		}
		fmt.Fprintln(stderr, pruneWarning)
	}
	if n := plan.Deletes(); n > 0 && !o.yes {
		ok, err := a.confirm(cmd.Context(), fmt.Sprintf("Delete %d certificate(s)? [y/N] ", n))
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

// confirm asks on the terminal openTTY opens. Only "y" or "yes" confirms, and
// cancelling ctx, as an interrupt does, answers no.
func (a *app) confirm(ctx context.Context, prompt string) (bool, error) {
	tty, err := a.openTTY()
	if err != nil {
		return false, fmt.Errorf("cannot open the terminal to confirm, pass --yes to skip confirmation: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	type reply struct {
		line string
		err  error
	}
	// Only this goroutine reads the terminal. Closing it ends a pending
	// read, and the buffered channel lets the goroutine finish after
	// confirm returns.
	replies := make(chan reply, 1)
	go func() {
		line, err := bufio.NewReader(tty).ReadString('\n')
		replies <- reply{line, err}
	}()
	var r reply
	select {
	case <-ctx.Done():
		// End the line the interrupt left the prompt on.
		fmt.Fprintln(tty)
		return false, nil
	case r = <-replies:
	}
	// EOF before a newline aborts, whatever was typed.
	if errors.Is(r.err, io.EOF) {
		return false, nil
	}
	if r.err != nil {
		return false, fmt.Errorf("read confirmation: %w", r.err)
	}
	answer := strings.ToLower(strings.TrimSpace(r.line))
	return answer == "y" || answer == "yes", nil
}
