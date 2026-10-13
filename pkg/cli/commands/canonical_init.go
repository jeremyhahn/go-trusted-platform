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
// call to the daemon's pre-unseal /init endpoint through the gate SDK
// client. The flag set is identical to qrdb / xkmsd / quicbaasd.
package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	platformbarrier "github.com/jeremyhahn/go-trusted-platform/pkg/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gate"
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
// validated for membership and forwarded as InitRequest.CredentialSealStrategy,
// for the ceremony; platformd initializes the barrier with its configured
// barrier.seal_strategy. Backend-specific failures (missing HSM, no TPM, no
// cloud credentials) surface from the daemon.
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
	officerFlags    []string
	officers        []gate.InitOfficer
	hostname        string
	sans            string
	adminBundle     string
	force           bool
	gateEndpoint    string
	loopbackHTTP    bool
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

// Steps of the canonical init flow, named by ErrInitStepFailed.
const (
	InitStepGateClient   = "create pre-unseal gate client"
	InitStepGateInit     = "run init on the pre-unseal gate"
	InitStepRenderOutput = "render init summary"
)

// ErrInitStepFailed indicates a step of platformctl init failed. Init
// never degrades to a summary: the operator must see which step broke.
type ErrInitStepFailed struct {
	// Step names the failed step (one of the InitStep constants).
	Step string
	// Err is the underlying failure.
	Err error
}

// Error returns a human-readable description.
func (e *ErrInitStepFailed) Error() string {
	return "init: failed to " + e.Step + ": " + e.Err.Error()
}

// Unwrap returns the underlying failure.
func (e *ErrInitStepFailed) Unwrap() error {
	return e.Err
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

// ErrAdminBundleEmpty indicates the daemon's /init returned an empty
// admin bundle, which the canonical init contract forbids. The bundle
// is the only artifact the operator can use to authenticate to the new
// platform, so dropping it on the floor must be a hard error rather
// than silently producing an unusable bundle.
type ErrAdminBundleEmpty struct{}

// Error returns a human-readable description.
func (e *ErrAdminBundleEmpty) Error() string {
	return "init response did not include admin certificate or key; the platform did not return an admin bundle"
}

// ErrAdminBundleIsDirectory is returned before init when --admin-bundle
// names a directory. The bundle could never be moved onto it, and the
// platform issues the bundle only once.
type ErrAdminBundleIsDirectory struct {
	// Path is the directory --admin-bundle named.
	Path string
}

// Error returns a human-readable description.
func (e *ErrAdminBundleIsDirectory) Error() string {
	return "admin bundle " + e.Path + " is a directory; name a file"
}

// ErrAdminBundleNotInPlace is returned when the bundle was written and
// synced but could not be moved to its path. The temporary file is kept,
// because the platform issues the bundle only once.
type ErrAdminBundleNotInPlace struct {
	// Path is where the bundle was meant to go.
	Path string
	// TempPath is the file that holds the bundle.
	TempPath string
	// Err is the close or rename failure.
	Err error
}

// Error returns a human-readable description naming the kept file.
func (e *ErrAdminBundleNotInPlace) Error() string {
	return "admin bundle saved at " + e.TempPath + " but not moved to " + e.Path +
		" (" + e.Err.Error() + "); move it by hand, the platform will not issue it again"
}

// Unwrap returns the close or rename failure.
func (e *ErrAdminBundleNotInPlace) Unwrap() error { return e.Err }

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

// ErrInvalidOfficerFlag is returned when an --officer value is not of the
// form username=path, or names a username twice.
type ErrInvalidOfficerFlag struct {
	// Value is the rejected --officer value.
	Value string
	// Reason says what is wrong with it.
	Reason string
}

// Error returns a human-readable description.
func (e *ErrInvalidOfficerFlag) Error() string {
	return fmt.Sprintf("init: invalid --officer %q: %s", e.Value, e.Reason)
}

// ErrOfficerCount is returned when a Shamir init does not name exactly one
// --officer per share. Each officer is enrolled with the barrier's share
// ceremony and receives one share, so the two counts must match.
type ErrOfficerCount struct {
	// Officers is the number of --officer flags given.
	Officers int
	// Shares is the --shares value.
	Shares int
}

// Error returns a human-readable description.
func (e *ErrOfficerCount) Error() string {
	return fmt.Sprintf("init: --barrier-strategy=shamir needs one --officer per share: got %d for --shares %d",
		e.Officers, e.Shares)
}

// ErrOfficerCSRUnreadable is returned when an officer's CSR file cannot be
// read. It is raised before /init is sent.
type ErrOfficerCSRUnreadable struct {
	// Username is the officer the file belongs to.
	Username string
	// Path is the CSR file named by --officer.
	Path string
	// Err is the read failure.
	Err error
}

// Error returns a human-readable description.
func (e *ErrOfficerCSRUnreadable) Error() string {
	return fmt.Sprintf("init: officer %q: cannot read CSR %s: %v", e.Username, e.Path, e.Err)
}

// Unwrap returns the read failure.
func (e *ErrOfficerCSRUnreadable) Unwrap() error { return e.Err }

// ErrLoopbackHTTPNotEnabled is returned when --gate-endpoint names a
// loopback HTTP address without --loopback-http. A lost /init response
// is replayed only over the Unix socket, so HTTP is never implied.
type ErrLoopbackHTTPNotEnabled struct {
	Endpoint string
}

// Error returns a human-readable description.
func (e *ErrLoopbackHTTPNotEnabled) Error() string {
	return fmt.Sprintf("init: --gate-endpoint %s is loopback HTTP; pass --loopback-http to use it (a lost response cannot be replayed over HTTP)", e.Endpoint)
}

// ErrLoopbackHTTPConflict is returned when --loopback-http is combined
// with a unix:// --gate-endpoint.
type ErrLoopbackHTTPConflict struct {
	Endpoint string
}

// Error returns a human-readable description.
func (e *ErrLoopbackHTTPConflict) Error() string {
	return fmt.Sprintf("init: --loopback-http contradicts --gate-endpoint %s", e.Endpoint)
}

// NewInitCommand builds the canonical root "init" command.
func NewInitCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &canonicalInitFlags{}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the barrier, CA, admin cert and roles in one call",
		Long: `Bootstrap a fresh platform in one call.

Canonical init command per docs/08-bootstrap-auth-architecture.md §6.
Runs before the barrier is unsealed, so it talks to the daemon's
pre-unseal /init endpoint, not to the SDK transports (which bind only
after unseal). The endpoint is --gate-endpoint, else the socket of the
current local context, else unix:///run/platformd.sock. Only a unix://
socket or a loopback address is accepted: the request carries both PINs.

Loopback HTTP (127.0.0.1:9446) is opt-in with --loopback-http. WARNING:
the daemon replays a lost /init response only over the Unix socket, to
the user that sent it. Over HTTP a lost response loses the one-shot
admin bundle for good, and any local process can reach the port.

The admin bundle (certificate, private key, SPKI pin) is returned once.
--admin-bundle is prepared before /init is sent, written 0600, and
never echoed: init then prints only a summary (ceremony ID, state, SPKI
pin, bundle location). With the default --admin-bundle=- the bundle is
the only thing on stdout and the summary goes to stderr.

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
  PLATFORMCTL_ADMIN_BUNDLE        equivalent to --admin-bundle
  PLATFORMCTL_GATE_ENDPOINT       equivalent to --gate-endpoint
  PLATFORMCTL_LOOPBACK_HTTP       equivalent to --loopback-http`,
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
	cmd.Flags().StringArrayVar(&f.officerFlags, "officer", nil,
		"Security Officer as username=path/to/csr.pem, once per share (required when --barrier-strategy=shamir)")
	cmd.Flags().StringVar(&f.hostname, "hostname", "",
		"FQDN written into the admin/server certificate CN")
	cmd.Flags().StringVar(&f.sans, "sans", "",
		"Comma-separated additional DNS / IP SANs")
	cmd.Flags().StringVar(&f.adminBundle, "admin-bundle", "-",
		"Path for the admin client cert+key bundle (default: stdout, one-shot)")
	cmd.Flags().BoolVar(&f.force, "force", false,
		"Overwrite --admin-bundle if it already exists (refuses by default)")
	cmd.Flags().StringVar(&f.gateEndpoint, "gate-endpoint", "",
		"Pre-unseal endpoint: unix://<socket>, or a loopback ip:port with --loopback-http (default: local context socket, else "+defaultGateSocket+")")
	cmd.Flags().BoolVar(&f.loopbackHTTP, "loopback-http", false,
		"Send /init over loopback HTTP ("+gate.DefaultHTTPAddr+" unless --gate-endpoint names one). WARNING: a lost response cannot be replayed over HTTP, so the one-shot admin bundle is lost with it; prefer the Unix socket")
}

// defaultGateSocket is the endpoint init uses with no --gate-endpoint,
// no --loopback-http and no local context: the daemon's default socket.
const defaultGateSocket = gate.UnixScheme + platform.DefaultUnixSocket

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
		"gate-endpoint":    "GATE_ENDPOINT",
		"loopback-http":    "LOOPBACK_HTTP",
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
		if len(f.officerFlags) != f.shares {
			return &ErrOfficerCount{Officers: len(f.officerFlags), Shares: f.shares}
		}
		officers, err := readInitOfficers(f.officerFlags)
		if err != nil {
			return err
		}
		f.officers = officers
	} else if f.shares != 0 || f.threshold != 0 || len(f.officerFlags) != 0 {
		return &MessageError{Msg: "init: --shares / --threshold / --officer only valid when --barrier-strategy=shamir"}
	}
	return validateGateTransport(f.gateEndpoint, f.loopbackHTTP)
}

// validateGateTransport makes loopback HTTP explicit: an HTTP
// --gate-endpoint needs --loopback-http, and --loopback-http cannot name
// a Unix socket. gate.NewClient still decides whether the address itself
// is acceptable.
func validateGateTransport(endpoint string, loopbackHTTP bool) error {
	if endpoint == "" {
		return nil
	}
	isSocket := strings.HasPrefix(endpoint, gate.UnixScheme)
	if loopbackHTTP && isSocket {
		return &ErrLoopbackHTTPConflict{Endpoint: endpoint}
	}
	if !loopbackHTTP && !isSocket {
		return &ErrLoopbackHTTPNotEnabled{Endpoint: endpoint}
	}
	return nil
}

// buildInitRequest maps the validated canonical init flag set onto the
// pre-unseal /init request. Shares and Threshold are only populated for
// the shamir strategy because every other backend ignores them.
//
// Strategy-specific flag interpretation lives here so that test
// harnesses can verify the per-strategy mapping without a running
// daemon.
func buildInitRequest(f *canonicalInitFlags) *gate.InitRequest {
	req := &gate.InitRequest{
		SOPIN:                  f.soPin,
		UserPIN:                f.userPin,
		Hostname:               f.hostname,
		SANs:                   parseCommaSeparated(f.sans),
		CredentialSealStrategy: f.barrierStrategy,
	}
	if f.barrierStrategy == "shamir" {
		req.Shares = f.shares
		req.Threshold = f.threshold
		req.Officers = f.officers
	}
	return req
}

// readInitOfficers checks every --officer username=path value, then reads
// each named CSR file, so a malformed value or an unreadable file fails the
// command before /init is sent. The gate checks that each CSR parses and is
// self-signed.
func readInitOfficers(values []string) ([]gate.InitOfficer, error) {
	paths := make([]string, 0, len(values))
	officers := make([]gate.InitOfficer, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		username, path, found := strings.Cut(value, "=")
		if !found || username == "" || path == "" {
			return nil, &ErrInvalidOfficerFlag{Value: value, Reason: "want username=path/to/csr.pem"}
		}
		if _, dup := seen[username]; dup {
			return nil, &ErrInvalidOfficerFlag{Value: value, Reason: "username given twice"}
		}
		seen[username] = struct{}{}
		paths = append(paths, path)
		officers = append(officers, gate.InitOfficer{Username: username})
	}
	for i, path := range paths {
		csrPEM, err := os.ReadFile(path)
		if err != nil {
			return nil, &ErrOfficerCSRUnreadable{Username: officers[i].Username, Path: path, Err: err}
		}
		officers[i].CSRPEM = string(csrPEM)
	}
	return officers, nil
}

// gateInitClient is the part of the gate SDK client init needs.
type gateInitClient interface {
	Init(ctx context.Context, req *gate.InitRequest) (*gate.InitResponse, error)
}

// renderFunc renders v to w in the operator's --output format.
type renderFunc func(w io.Writer, v any) error

// initSummary is what init renders after the bundle is written. It
// deliberately has no key field: the private key only ever reaches the
// bundle sink.
type initSummary struct {
	CeremonyID    string    `json:"ceremony_id,omitempty" yaml:"ceremony_id,omitempty"`
	State         string    `json:"state" yaml:"state"`
	InitializedAt time.Time `json:"initialized_at,omitempty" yaml:"initialized_at,omitempty"`
	SPKIPin       string    `json:"spki_pin,omitempty" yaml:"spki_pin,omitempty"`
	AdminBundle   string    `json:"admin_bundle" yaml:"admin_bundle"`
}

// runCanonicalInit sends the validated canonical init flag set to the
// daemon's pre-unseal /init endpoint. It does not open an SDK connection:
// before unseal none of the six SDK transports is bound.
func runCanonicalInit(cmd *cobra.Command, f *canonicalInitFlags, getFlags func() *cli.CommonFlags) error {
	flags := getFlags()
	client, err := gate.NewClient(resolveGateEndpoint(f.gateEndpoint, f.loopbackHTTP, flags))
	if err != nil {
		return &ErrInitStepFailed{Step: InitStepGateClient, Err: err}
	}
	format := cli.OutputFormatTable
	noColor := false
	if flags != nil {
		format = flags.OutputFormat
		noColor = flags.NoColor
	}
	render := func(w io.Writer, v any) error {
		return cli.NewPrinterWithWriter(format, noColor, w).Print(v)
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return executeCanonicalInit(ctx, cmd.OutOrStdout(), cmd.ErrOrStderr(), f, client, render)
}

// resolveGateEndpoint picks the pre-unseal endpoint: --gate-endpoint when
// set, else the loopback listener when --loopback-http opted in, else the
// socket of a local context, else the daemon's default socket. A context
// that cannot be loaded is not an error here: a fresh host typically has
// none. Without an explicit opt-in init always uses a Unix socket, the
// only transport on which a lost response can be replayed.
func resolveGateEndpoint(explicit string, loopbackHTTP bool, flags *cli.CommonFlags) string {
	if explicit != "" {
		return explicit
	}
	if loopbackHTTP {
		return gate.DefaultHTTPAddr
	}
	if flags != nil && flags.GetContext != nil {
		ctx, err := flags.GetContext()
		if err == nil && ctx.Type == cli.ContextTypeLocal && ctx.Local != nil && ctx.Local.SocketPath != "" {
			return gate.UnixScheme + ctx.Local.SocketPath
		}
	}
	return defaultGateSocket
}

// executeCanonicalInit prepares the bundle sink, sends /init, writes the
// returned admin bundle, then renders the sanitized summary. The sink is
// prepared first so an unwritable --admin-bundle fails before the daemon
// mints the one-shot bundle.
//
// When the bundle goes to stdout, stdout carries only the bundle and the
// summary goes to stderr, so the key is printed exactly once.
func executeCanonicalInit(ctx context.Context, stdout, stderr io.Writer, f *canonicalInitFlags, client gateInitClient, render renderFunc) error {
	sink, err := openBundleSink(stdout, f.adminBundle, f.force)
	if err != nil {
		return err
	}
	resp, err := client.Init(ctx, buildInitRequest(f))
	if err != nil {
		return &ErrInitStepFailed{Step: InitStepGateInit, Err: errors.Join(err, sink.abort())}
	}
	if resp == nil || resp.AdminCertPEM == "" || resp.AdminKeyPEM == "" {
		return errors.Join(&ErrAdminBundleEmpty{}, sink.abort())
	}
	if err := sink.commit(assembleAdminBundle(resp)); err != nil {
		return err
	}

	summaryOut := stdout
	if sink.toStdout() {
		summaryOut = stderr
	}
	summary := &initSummary{
		CeremonyID:    resp.CeremonyID,
		State:         string(resp.State),
		InitializedAt: resp.InitializedAt,
		SPKIPin:       resp.SPKIPin,
		AdminBundle:   sink.name(),
	}
	if err := render(summaryOut, summary); err != nil {
		return &ErrInitStepFailed{Step: InitStepRenderOutput, Err: err}
	}
	return nil
}

// bundleSink is where the admin bundle goes: stdout, or a file written
// via a 0600 temporary file in the same directory and renamed into place.
type bundleSink struct {
	stdout io.Writer
	path   string
	tmp    *os.File
}

// openBundleSink prepares the sink for path ("-" or "" means stdout).
// It refuses an existing file unless force is true.
func openBundleSink(stdout io.Writer, path string, force bool) (*bundleSink, error) {
	if path == "" || path == "-" {
		return &bundleSink{stdout: stdout}, nil
	}
	// Everything that can stop the bundle reaching path is checked here,
	// before /init: the platform issues the bundle only once.
	info, err := os.Stat(path)
	switch {
	case err == nil && info.IsDir():
		return nil, &ErrAdminBundleIsDirectory{Path: path}
	case err == nil && !force:
		return nil, &ErrAdminBundleExists{Path: path}
	case err != nil && !os.IsNotExist(err):
		return nil, &WrappedError{Msg: fmt.Sprintf("init: stat %s", path), Err: err}
	}
	// Creating the temporary file proves the parent directory is writable.
	// os.CreateTemp creates the file 0600; the bundle holds a private key.
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("init: prepare %s", path), Err: err}
	}
	return &bundleSink{path: path, tmp: tmp}, nil
}

func (s *bundleSink) toStdout() bool { return s.tmp == nil }

// name is the sink as rendered in the summary.
func (s *bundleSink) name() string {
	if s.toStdout() {
		return "stdout"
	}
	return s.path
}

// commit writes bundle and, for a file sink, renames it into place.
func (s *bundleSink) commit(bundle string) error {
	if s.toStdout() {
		if _, err := io.WriteString(s.stdout, bundle); err != nil {
			return &WrappedError{Msg: "init: write admin bundle to stdout", Err: err}
		}
		return nil
	}
	if _, err := io.WriteString(s.tmp, bundle); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("init: write %s", s.path), Err: errors.Join(err, s.abort())}
	}
	if err := s.tmp.Sync(); err != nil {
		return &WrappedError{Msg: fmt.Sprintf("init: sync %s", s.path), Err: errors.Join(err, s.abort())}
	}
	// The bundle is on disk now; from here a failure keeps the file.
	if err := s.tmp.Close(); err != nil {
		return &ErrAdminBundleNotInPlace{Path: s.path, TempPath: s.tmp.Name(), Err: err}
	}
	if err := os.Rename(s.tmp.Name(), s.path); err != nil {
		return &ErrAdminBundleNotInPlace{Path: s.path, TempPath: s.tmp.Name(), Err: err}
	}
	return nil
}

// abort discards a file sink that was never committed.
func (s *bundleSink) abort() error {
	if s.toStdout() {
		return nil
	}
	return errors.Join(s.tmp.Close(), os.Remove(s.tmp.Name()))
}

// assembleAdminBundle joins the certificate and private key into a
// single PEM bundle with deterministic ordering: certificate first,
// then private key. The format is identical to what
// tls.LoadX509KeyPair(path, path) accepts.
func assembleAdminBundle(resp *gate.InitResponse) string {
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
