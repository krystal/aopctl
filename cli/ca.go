package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/krystal/aopctl/aopctl"
)

const maxCertInput = 1 << 20

var (
	// Kubernetes object names: a Secret name is a DNS subdomain and a
	// namespace is a DNS label.
	secretNamePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	namespacePattern  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// opItem is a 1Password item template, as read by "op item create -".
type opItem struct {
	Title    string    `json:"title"`
	Category string    `json:"category"`
	Fields   []opField `json:"fields"`
}

type opField struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Purpose string `json:"purpose,omitempty"`
	Label   string `json:"label"`
	Value   string `json:"value"`
}

func newCACmd(a *app) *cobra.Command {
	return newGroupCmd("ca", "Create or describe the client CA", newCACreateCmd(a), newCAShowCmd(a))
}

type caCreateOptions struct {
	name    string
	keyType string
	days    int
	title   string
}

func newCACreateCmd(a *app) *cobra.Command {
	o := &caCreateOptions{}
	cmd := &cobra.Command{
		Use:   "create [flags] | op item create --vault <vault> -",
		Short: "Create a CA and print a 1Password item template",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.caCreate(cmd, o)
		},
	}
	cmd.Flags().StringVar(&o.name, "name", "aopctl AOP CA", "CA common name")
	keyTypeFlag(cmd, &o.keyType)
	cmd.Flags().IntVar(&o.days, "days", 3650, "validity in days")
	cmd.Flags().StringVar(&o.title, "title", "", "1Password item title (default: the common name)")
	return cmd
}

func (a *app) caCreate(cmd *cobra.Command, o *caCreateOptions) error {
	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if err := validateKeyType(o.keyType); err != nil {
		return err
	}
	if err := validateDays(o.days); err != nil {
		return err
	}
	if a.stdoutIsTerminal(stdout) {
		return errors.New("refusing to write the CA key to a terminal: pipe the output to \"op item create --vault <vault> -\"")
	}
	title := o.title
	if title == "" {
		title = o.name
	}

	cert, key, err := aopctl.CreateCA(aopctl.CARequest{CommonName: o.name, KeyType: aopctl.KeyType(o.keyType), Days: o.days, Now: a.now()})
	if err != nil {
		return err
	}
	keyPEM, err := aopctl.EncodePrivateKeyPEM(key)
	if err != nil {
		return err
	}
	fp := aopctl.Fingerprint(cert)
	expires := cert.NotAfter.UTC().Format(time.RFC3339)
	item := opItem{
		Title:    title,
		Category: "SECURE_NOTE",
		Fields: []opField{
			{
				ID: "notesPlain", Type: "STRING", Purpose: "NOTES", Label: "notesPlain",
				Value: fmt.Sprintf("Cloudflare Authenticated Origin Pulls client CA, created by aopctl. Expires %s.", expires),
			},
			{ID: "ca_cert", Type: "STRING", Label: "ca_cert", Value: aopctl.EncodeCertificatePEM(cert)},
			{ID: "ca_key", Type: "CONCEALED", Label: "ca_key", Value: keyPEM},
			{ID: "fingerprint_sha256", Type: "STRING", Label: "fingerprint_sha256", Value: fp},
		},
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(item); err != nil {
		return fmt.Errorf("write item template: %w", err)
	}

	fmt.Fprintf(stderr, `Created CA %q (%s), expires %s.
SHA-256 fingerprint: %s

Next steps:
  1. Reference the item's ca_cert and ca_key fields as AOP_CA_CERT and
     AOP_CA_KEY in the env file you pass to op run.
  2. Pin the fingerprint in traefik-plugin-cloudflare-origin's
     clientCertFingerprints.
  3. Create the Traefik Secret from the certificate with
     op read "op://<vault>/<item>/ca_cert" | %s ca show --secret <name>
`, o.name, describeKey(cert.PublicKey), expires, fp, a.commandPath())
	return nil
}

type caShowOptions struct {
	secret    string
	namespace string
}

func newCAShowCmd(a *app) *cobra.Command {
	o := &caShowOptions{}
	cmd := &cobra.Command{
		Use:   "show [flags] < ca.crt",
		Short: "Describe the CA certificate read from stdin",
		Args:  noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.caShow(cmd, o)
		},
	}
	cmd.Flags().StringVar(&o.secret, "secret", "", "print only a Kubernetes Secret with this name holding the certificate")
	cmd.Flags().StringVar(&o.namespace, "namespace", "", "namespace for the Secret (requires --secret)")
	return cmd
}

func (a *app) caShow(cmd *cobra.Command, o *caShowOptions) error {
	stdin, stdout, stderr := cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
	secret, namespace := o.secret, o.namespace
	if namespace != "" && secret == "" {
		return usagef("--namespace requires --secret")
	}
	if secret != "" && (len(secret) > 253 || !secretNamePattern.MatchString(secret)) {
		return usagef("invalid --secret %q: want a Kubernetes object name", secret)
	}
	if namespace != "" && (len(namespace) > 63 || !namespacePattern.MatchString(namespace)) {
		return usagef("invalid --namespace %q: want a Kubernetes namespace name", namespace)
	}
	if a.stdinIsTerminal(stdin) {
		return errors.New("ca show reads the CA certificate PEM from stdin: pipe it in, for example with op read")
	}

	data, err := io.ReadAll(io.LimitReader(stdin, maxCertInput))
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	cert, err := aopctl.ParseCertificatePEM(string(data))
	if err != nil {
		return fmt.Errorf("stdin: %w", err)
	}
	warnings := aopctl.CAProfileWarnings(cert)

	if secret != "" {
		for _, w := range warnings {
			fmt.Fprintf(stderr, "warning: %s\n", w)
		}
		writeSecretManifest(stdout, secret, namespace, aopctl.EncodeCertificatePEM(cert))
		return nil
	}

	fmt.Fprintf(stdout, "Subject:     %s\n", cert.Subject)
	fmt.Fprintf(stdout, "Fingerprint: %s\n", aopctl.Fingerprint(cert))
	fmt.Fprintf(stdout, "Not before:  %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(stdout, "Not after:   %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(stdout, "Key type:    %s\n", describeKey(cert.PublicKey))
	for _, w := range warnings {
		fmt.Fprintf(stdout, "Warning:     %s\n", w)
	}
	return nil
}

// writeSecretManifest writes the CA Secret from the first example in the
// traefik-plugin-cloudflare-origin README.
func writeSecretManifest(w io.Writer, name, namespace, certPEM string) {
	fmt.Fprintf(w, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n", name)
	if namespace != "" {
		fmt.Fprintf(w, "  namespace: %s\n", namespace)
	}
	fmt.Fprint(w, "type: Opaque\nstringData:\n  ca.crt: |\n")
	for line := range strings.SplitSeq(strings.TrimSpace(certPEM), "\n") {
		fmt.Fprintf(w, "    %s\n", line)
	}
}

// loadCA parses the CA pair from AOP_CA_CERT and AOP_CA_KEY and checks that
// the key matches.
func loadCA(certPEM, keyPEM string) (*x509.Certificate, crypto.Signer, error) {
	cert, err := parseCACert(certPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := aopctl.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("AOP_CA_KEY: %w", err)
	}
	if pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(cert.PublicKey) {
		return nil, nil, errors.New("AOP_CA_KEY does not match the certificate in AOP_CA_CERT")
	}
	return cert, key, nil
}

// parseCACert parses AOP_CA_CERT.
func parseCACert(certPEM string) (*x509.Certificate, error) {
	cert, err := aopctl.ParseCACertificate(certPEM)
	if errors.Is(err, aopctl.ErrNotCA) {
		return nil, errors.New("AOP_CA_CERT is not a CA certificate")
	}
	if err != nil {
		return nil, fmt.Errorf("AOP_CA_CERT: %w", err)
	}
	return cert, nil
}

func describeKey(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("unknown (%T)", pub)
}
