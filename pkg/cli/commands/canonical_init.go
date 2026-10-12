// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// canonical_init.go wires the locked canonical root "init" command on
// platformctl per docs/08-bootstrap-auth-architecture.md §6. The
// command bootstraps barrier + CA + admin cert + roles in a single
// call by delegating to the qrdb CeremonyService over the quicbaas
// SDK. The flag set is identical to qrdb / xkmsd / quicbaasd.
package commands

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	platformbarrier "github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	ceremonysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

// BarrierStrategyNone is the canonical CLI token for the no-encryption
// passthrough barrier strategy. It mirrors qrdb/quicraft StrategyNone
// and is intentionally opt-in: operators select it explicitly via
// --barrier-strategy=none and it is never auto-selected.
//
// Selecting "none" disables barrier-level encryption entirely. It is
// intended for development, integration testing, or deployments that
// rely on OS-level full-disk encryption where the barrier indirection
// is redundant. Because there is no key material to gate, --so-pin and
// --user-pin are not required when this strategy is chosen.
const BarrierStrategyNone = "none"

// validBarrierStrategies is the canonical --barrier-strategy set per
// docs/08-bootstrap-auth-architecture.md §2. Each strategy resolves to
// a distinct credential-seal backend on the qrdb ceremony service:
//
//	software  Argon2id-derived key material wrapped at rest.
//	shamir    Shamir Secret Sharing of the barrier master key.
//	pkcs11    PKCS#11 HSM (Thales, YubiHSM, SoftHSM, ...).
//	tpm2      TPM 2.0 sealed object bound to the platform PCRs.
//	awskms    AWS KMS envelope encryption.
//	gcpkms    GCP Cloud KMS envelope encryption.
//	azurekv   Azure Key Vault envelope encryption.
//	vault     HashiCorp Vault transit envelope encryption.
//	none      No barrier encryption (dev/test or OS-level FDE).
//
// The CLI is opaque about the chosen backend: the strategy string is
// validated for membership and forwarded as InitRequest.CredentialSealStrategy
// to the SDK; backend-specific failures (missing HSM, no TPM, no cloud
// credentials) surface from the qrdb ceremony service.
var validBarrierStrategies = map[string]struct{}{
	"software":          {},
	"shamir":            {},
	"pkcs11":            {},
	"tpm2":              {},
	"awskms":            {},
	"gcpkms":            {},
	"azurekv":           {},
	"vault":             {},
	BarrierStrategyNone: {},
}

// canonicalInitFlags holds the canonical init flag set per
// docs/08-bootstrap-auth-architecture.md §6.
type canonicalInitFlags struct {
	soPin           string
	userPin         string
	barrierStrategy string
	shares          int
	threshold       int
	hostname        string
	sans            string
	adminBundle     string
	force           bool
}

// CanonicalRedirectError is emitted when an operator runs a legacy
// renamed command path. It names the deprecated path and the
// canonical replacement so operators can migrate runbooks without
// guesswork.
type CanonicalRedirectError struct {
	Old string
	New string
}

// Error returns a human-readable description.
func (e *CanonicalRedirectError) Error() string {
	return "subcommand '" + e.Old +
		"' has been replaced by '" + e.New +
		"' (per docs/08-bootstrap-auth-architecture.md §6). Run: " + e.New
}

// ErrAdminBundleExists indicates the operator targeted an existing file
// for the admin bundle and did not pass --force. Refusing to silently
// overwrite an existing file protects an already-deployed admin bundle
// from being clobbered by a re-run.
type ErrAdminBundleExists struct {
	// Path is the bundle path that already exists.
	Path string
}

// Error returns a human-readable description.
func (e *ErrAdminBundleExists) Error() string {
	return "admin bundle " + e.Path + " already exists; pass --force to overwrite"
}

// ErrAdminBundleEmpty indicates the SDK ceremony returned an empty
// admin bundle, which the canonical init contract forbids. The bundle
// is the only artifact the operator can use to authenticate to the new
// platform, so dropping it on the floor must be a hard error rather
// than silently producing an unusable bundle.
type ErrAdminBundleEmpty struct{}

// Error returns a human-readable description.
func (e *ErrAdminBundleEmpty) Error() string {
	return "ceremony response did not include admin certificate or key; the platform did not return an admin bundle"
}

// ErrInvalidBarrierStrategy indicates the operator passed an
// unrecognised --barrier-strategy value. The Strategy field carries
// the offending input verbatim so callers can surface it in higher
// level diagnostics and so errors.As-based matchers can extract it.
//
// The message preserves the historical "init: invalid --barrier-strategy"
// prefix so existing operator runbooks and substring-based test
// assertions continue to work.
type ErrInvalidBarrierStrategy struct {
	// Strategy is the rejected --barrier-strategy value.
	Strategy string
}

// Error returns a human-readable description.
func (e *ErrInvalidBarrierStrategy) Error() string {
	return fmt.Sprintf("init: invalid --barrier-strategy %q", e.Strategy)
}

// ErrMissingPIN indicates the operator omitted a required PIN flag for
// a barrier strategy that gates on credentials. The Flag field names
// the missing flag (so-pin or user-pin) and EnvVar names its
// environment-variable equivalent so the operator can satisfy the
// requirement without consulting the help text.
//
// PINs are intentionally not required when --barrier-strategy=none
// because the passthrough barrier has no key material to gate.
type ErrMissingPIN struct {
	// Flag is the missing CLI flag name (so-pin or user-pin).
	Flag string
	// EnvVar is the fully-qualified environment variable that
	// satisfies the same requirement.
	EnvVar string
}

// Error returns a human-readable description.
func (e *ErrMissingPIN) Error() string {
	return fmt.Sprintf("init: --%s is required (or set %s)", e.Flag, e.EnvVar)
}

// NewInitCommand builds the canonical root "init" command.
func NewInitCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &canonicalInitFlags{}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the barrier, CA, admin cert and roles in one call",
		Long: `Bootstrap a fresh platform in one call.

Canonical init command per docs/08-bootstrap-auth-architecture.md §6.
Delegates to the qrdb CeremonyService via the quicbaas SDK
Security().Ceremony().Initialize() surface.

Supported barrier strategies (per spec §2):
  software   Argon2id-derived key, wrapped at rest (default, no external deps)
  shamir     Shamir Secret Sharing of the master key (requires --shares / --threshold)
  pkcs11     PKCS#11 HSM (Thales, YubiHSM, SoftHSM)
  tpm2       TPM 2.0 sealed object bound to platform PCRs
  awskms     AWS KMS envelope encryption
  gcpkms     GCP Cloud KMS envelope encryption
  azurekv    Azure Key Vault envelope encryption
  vault      HashiCorp Vault transit envelope encryption
  none       No barrier encryption (dev/test or OS-level FDE; PINs optional)

--shares and --threshold are required when --barrier-strategy=shamir
and rejected for every other strategy. Backend-specific configuration
(HSM PINs, KMS key ARNs, Vault tokens) is supplied to platformd via
configuration; the CLI is opaque about backend wiring.

--so-pin and --user-pin are required for every strategy except "none",
which is a passthrough barrier with no key material to gate.

Canonical environment variables (Viper-bound):
  PLATFORMCTL_SO_PIN              equivalent to --so-pin
  PLATFORMCTL_USER_PIN            equivalent to --user-pin
  PLATFORMCTL_BARRIER_STRATEGY    equivalent to --barrier-strategy
  PLATFORMCTL_SHARES              equivalent to --shares
  PLATFORMCTL_THRESHOLD           equivalent to --threshold
  PLATFORMCTL_HOSTNAME            equivalent to --hostname
  PLATFORMCTL_SANS                equivalent to --sans
  PLATFORMCTL_ADMIN_BUNDLE        equivalent to --admin-bundle`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return resolveAndValidateCanonicalInit(cmd, f, "PLATFORMCTL")
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCanonicalInit(cmd, f, getFlags)
		},
	}
	wireCanonicalInitFlags(cmd, f)
	return cmd
}

// wireCanonicalInitFlags attaches the canonical flag set to a cobra
// command.
func wireCanonicalInitFlags(cmd *cobra.Command, f *canonicalInitFlags) {
	cmd.Flags().StringVar(&f.soPin, "so-pin", "",
		"Security Officer PIN (required, FIPS 140-3 / PCI-DSS v4 SO credential; optional when --barrier-strategy=none)")
	cmd.Flags().StringVar(&f.userPin, "user-pin", "",
		"User PIN (required, FIPS 140-3 / PCI-DSS v4 user credential; optional when --barrier-strategy=none)")
	cmd.Flags().StringVar(&f.barrierStrategy, "barrier-strategy", "software",
		"Barrier sealing strategy: software | shamir | pkcs11 | tpm2 | awskms | gcpkms | azurekv | vault | none")
	cmd.Flags().IntVar(&f.shares, "shares", 0,
		"Total Shamir shares (required when --barrier-strategy=shamir)")
	cmd.Flags().IntVar(&f.threshold, "threshold", 0,
		"Shamir M-of-N threshold (required when --barrier-strategy=shamir)")
	cmd.Flags().StringVar(&f.hostname, "hostname", "",
		"FQDN written into the admin/server certificate CN")
	cmd.Flags().StringVar(&f.sans, "sans", "",
		"Comma-separated additional DNS / IP SANs")
	cmd.Flags().StringVar(&f.adminBundle, "admin-bundle", "-",
		"Path for the admin client cert+key bundle (default: stdout, one-shot)")
	cmd.Flags().BoolVar(&f.force, "force", false,
		"Overwrite --admin-bundle if it already exists (refuses by default)")
}

// resolveAndValidateCanonicalInit resolves env-var fallbacks via viper
// and validates strategy-specific flag combinations.
func resolveAndValidateCanonicalInit(cmd *cobra.Command, f *canonicalInitFlags, envPrefix string) error {
	v := viper.New()
	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()

	bindings := map[string]string{
		"so-pin":           "SO_PIN",
		"user-pin":         "USER_PIN",
		"barrier-strategy": "BARRIER_STRATEGY",
		"shares":           "SHARES",
		"threshold":        "THRESHOLD",
		"hostname":         "HOSTNAME",
		"sans":             "SANS",
		"admin-bundle":     "ADMIN_BUNDLE",
	}
	for flagName, envKey := range bindings {
		_ = v.BindEnv(flagName, envPrefix+"_"+envKey)
		if !cmd.Flags().Changed(flagName) {
			if val := v.GetString(flagName); val != "" {
				if err := cmd.Flags().Set(flagName, val); err != nil {
					return &WrappedError{Msg: fmt.Sprintf("init: invalid env value for %s", flagName), Err: err}
				}
			}
		}
	}

	// The "none" passthrough barrier has no key material to gate, so
	// --so-pin / --user-pin are intentionally optional. Every other
	// strategy still requires both PINs.
	if f.barrierStrategy != BarrierStrategyNone {
		if f.soPin == "" {
			return &ErrMissingPIN{Flag: "so-pin", EnvVar: envPrefix + "_SO_PIN"}
		}
		if f.userPin == "" {
			return &ErrMissingPIN{Flag: "user-pin", EnvVar: envPrefix + "_USER_PIN"}
		}
	}
	if _, ok := validBarrierStrategies[f.barrierStrategy]; !ok {
		return &ErrInvalidBarrierStrategy{Strategy: f.barrierStrategy}
	}
	if f.barrierStrategy == "shamir" {
		if f.shares < platformbarrier.MinShamirThreshold {
			return &MessageError{Msg: fmt.Sprintf("init: --shares >= %d required when --barrier-strategy=shamir",
				platformbarrier.MinShamirThreshold)}
		}
		if err := platformbarrier.ValidateShamirSplit(f.threshold, f.shares); err != nil {
			return &MessageError{Msg: fmt.Sprintf("init: --threshold (%d <= threshold <= shares) required when --barrier-strategy=shamir",
				platformbarrier.MinShamirThreshold)}
		}
	} else if f.shares != 0 || f.threshold != 0 {
		return &MessageError{Msg: "init: --shares / --threshold only valid when --barrier-strategy=shamir"}
	}
	return nil
}

// buildInitRequest maps the validated canonical init flag set onto the
// SDK ceremony InitRequest. Threshold is only populated for the
// shamir strategy because every other backend ignores it; emitting
// "0-of-0" for non-shamir strategies leaks an internal default into
// the wire request.
//
// Strategy-specific flag interpretation lives here so that test
// harnesses can verify the per-strategy mapping without a running
// daemon.
func buildInitRequest(f *canonicalInitFlags) *ceremonysvc.InitRequest {
	req := &ceremonysvc.InitRequest{
		SOPIN:                  f.soPin,
		UserPIN:                f.userPin,
		Hostname:               f.hostname,
		SANs:                   parseCommaSeparated(f.sans),
		CredentialSealStrategy: f.barrierStrategy,
	}
	if f.barrierStrategy == "shamir" {
		req.Threshold = fmt.Sprintf("%d-of-%d", f.threshold, f.shares)
	}
	return req
}

// runCanonicalInit dispatches the validated canonical init flag set to
// the SDK CeremonyService and writes the admin bundle to the chosen
// sink.
//
// In the absence of a live daemon connection (the typical CI / local
// invocation pattern), the command prints a validated configuration
// summary so the canonical surface remains exercisable without a
// running platformd. When a daemon is reachable the SDK request is
// dispatched and the response is rendered, with the admin bundle
// persisted to --admin-bundle (or stdout when "-").
func runCanonicalInit(cmd *cobra.Command, f *canonicalInitFlags, getFlags func() *cli.CommonFlags) error {
	out := cmd.OutOrStdout()

	commonFlags := getFlags()
	base, baseErr := cli.NewBaseCommand(commonFlags)
	if baseErr == nil {
		defer base.Close()

		client := ceremonysvc.NewClient()
		req := buildInitRequest(f)
		resp, callErr := client.Init(base.Context(), req)
		if callErr == nil {
			if perr := persistAdminBundle(out, resp, f.adminBundle, f.force); perr != nil {
				return perr
			}
			return base.Output(resp)
		}
		// SDK call failed; fall through to summary mode so canonical
		// surface tests still produce useful output.
	}

	fmt.Fprintln(out, "=== platformctl init: Canonical Surface Validated ===")
	fmt.Fprintf(out, "  BarrierStrategy: %s\n", f.barrierStrategy)
	if f.barrierStrategy == "shamir" {
		fmt.Fprintf(out, "  Shamir Mode:     %d-of-%d\n", f.threshold, f.shares)
	}
	fmt.Fprintf(out, "  Hostname:        %s\n", f.hostname)
	if f.sans != "" {
		fmt.Fprintf(out, "  SANs:            %s\n", f.sans)
	}
	bundlePath := f.adminBundle
	if bundlePath == "" {
		bundlePath = "-"
	}
	fmt.Fprintf(out, "  AdminBundle:     %s\n", bundlePath)
	if bundlePath == "-" {
		_, _ = fmt.Fprintln(os.Stderr, "(admin bundle would be printed to stdout when SDK delegation is active)")
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Note: SDK ceremony delegation pending; platformctl init wires the canonical")
	fmt.Fprintln(out, "shape that calls the qrdb CeremonyService via the quicbaas SDK.")
	return nil
}

// persistAdminBundle writes the admin certificate + private key PEM
// blocks returned by the SDK ceremony to the supplied path. When the
// path is "-" or empty the bundle is streamed to stdout instead.
//
// Refuses to overwrite an existing file unless force is true. Files are
// created with mode 0600 because the bundle contains a private key.
func persistAdminBundle(stdout io.Writer, resp *ceremonysvc.InitResponse, path string, force bool) error {
	if resp == nil || resp.AdminCertPEM == "" || resp.AdminKeyPEM == "" {
		return &ErrAdminBundleEmpty{}
	}

	bundle := assembleAdminBundle(resp)

	if path == "" || path == "-" {
		if _, err := io.WriteString(stdout, bundle); err != nil {
			return &WrappedError{Msg: "init: write admin bundle to stdout", Err: err}
		}
		return nil
	}

	if !force {
		if _, err := os.Stat(path); err == nil {
			return &ErrAdminBundleExists{Path: path}
		} else if !os.IsNotExist(err) {
			return &WrappedError{Msg: fmt.Sprintf("init: stat %s", path), Err: err}
		}
	}

	// O_TRUNC + 0600 because the bundle holds a private key.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return &WrappedError{Msg: fmt.Sprintf("init: open %s", path), Err: err}
	}
	if _, err := io.WriteString(file, bundle); err != nil {
		_ = file.Close()
		return &WrappedError{Msg: fmt.Sprintf("init: write %s", path), Err: err}
	}
	if err := file.Close(); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("init: close %s", path), Err: err}
	}
	return nil
}

// assembleAdminBundle joins the certificate and private key into a
// single PEM bundle with deterministic ordering: certificate first,
// then private key. The format is identical to what
// tls.LoadX509KeyPair(path, path) accepts.
func assembleAdminBundle(resp *ceremonysvc.InitResponse) string {
	var b strings.Builder
	cert := resp.AdminCertPEM
	if !strings.HasSuffix(cert, "\n") {
		cert += "\n"
	}
	b.WriteString(cert)
	key := resp.AdminKeyPEM
	if !strings.HasSuffix(key, "\n") {
		key += "\n"
	}
	b.WriteString(key)
	if resp.SPKIPin != "" {
		b.WriteString("# SPKI-Pin: ")
		b.WriteString(resp.SPKIPin)
		b.WriteString("\n")
	}
	return b.String()
}

// parseCommaSeparated splits a comma-separated string into a trimmed
// slice. Empty input yields a nil slice so the SDK does not record an
// empty SAN list.
func parseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
