// Command deployer-pin provisions a local SSH host-key pin envelope for the
// bootstrap deployer / switch / fabric known_hosts store.
//
// The deployer SSH stack is fail-closed: it verifies the target host key
// against a pinned envelope resolved from the directory containing
// deployer.known_hosts_path, under (scope=service, owner=host, host). No
// trust-on-first-use path exists. This tool captures the host key the Go
// x/crypto/ssh stack actually negotiates against the target (matching what
// the deployer will see) and persists the pin via the go-quicbaas SDK
// knownhosts re-export.
//
// Provisioning a pin is NOT trust-on-first-use either: --expect-fingerprint is
// mandatory and carries the fingerprints the operator obtained out of band (on
// the target's console, `ssh-keygen -lf /etc/ssh/ssh_host_*.pub`). A key that
// matches none of them is never written, so a machine-in-the-middle on the
// provisioning network cannot become the trusted pin. docs/bootstrap/
// architecture.md rejects TOFU for the deployer and switch host keys precisely
// because the deployer host serves the install path for the whole fleet.
//
// The flag takes a comma-separated set rather than a single value because the
// operator cannot know in advance which of the host's keys the handshake will
// negotiate — that is chosen by the client/server algorithm preference, not by
// the operator. Every fingerprint in the set is one the operator verified on
// that host, so accepting any of them concedes nothing.
//
// Idempotent: an identical existing pin is left in place; a differing pin is
// rotated (removed then re-added) — safe only because the replacement key had
// to match an operator-asserted fingerprint to get this far.
//
// The whole workflow is [run], which never calls os.Exit and reaches the
// network and the filesystem only through the [deps] it is handed. main is a
// three-line shell around it: production dependencies in, exit code out. That
// split exists so the fail-closed ordering — validate, capture, compare, and
// only then open or mutate the store — is executable in a test rather than
// merely readable in the source.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	knownhosts "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/knownhosts"
	sshscope "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/scope"
	filestorage "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/storage/file"
	"golang.org/x/crypto/ssh"
)

var errCaptured = errors.New("host key captured")

// usageText names the channels a fingerprint may legitimately come from. An
// error that says only "flag required" invites the operator to read the value
// off the very connection being pinned, which is the attack the flag exists to
// stop — so the message has to say where, not just what.
const usageText = `usage: deployer-pin --host <ip> --dir <known_hosts_dir> --expect-fingerprint SHA256:<...>[,SHA256:<...>] [--owner <ip>] [--port 22]

--expect-fingerprint is mandatory: the pin store has no trust-on-first-use path.

Obtain the fingerprint over a channel OTHER than the SSH connection being pinned:
  - on the host's console:   ssh-keygen -lf /etc/ssh/ssh_host_*.pub
  - from the host's provisioning record, install log, or vendor key sheet

Pass every fingerprint the host holds — the SSH handshake, not you, decides
which key is negotiated.

  ssh-keyscan -t ecdsa <host> | ssh-keygen -lf -

reads the key back over the connection being verified, so it can CONFIRM a
fingerprint already recorded through one of the channels above. On its own it
proves nothing: a machine-in-the-middle answers keyscan with its own key.
`

func main() {
	err := run(context.Background(), os.Args[1:], productionDeps())
	report(err, os.Stderr)
	os.Exit(exitCode(err))
}

// deps carries every coupling to the outside world that run needs: the dial
// that captures a host key, the store that persists the pin, and where status
// output goes. Tests substitute all three; nothing else in run touches the
// network, the filesystem, or a global.
type deps struct {
	// capture returns the host key the target presents. Called at most once,
	// and only after the invocation has been fully validated.
	capture func(host string, port int) (ssh.PublicKey, error)

	// openStore creates dir if needed and opens the pin store rooted there.
	// Called only after the presented key has matched an expected
	// fingerprint, so a rejected key never causes a directory or a store
	// file to come into existence.
	openStore func(dir string) (knownhosts.Store, error)

	// stdout receives the one status line a successful run prints.
	stdout io.Writer
}

// productionDeps wires the real SSH dial and the real file-backed pin store.
func productionDeps() deps {
	return deps{
		capture:   captureHostKey,
		openStore: openFileStore,
		stdout:    os.Stdout,
	}
}

// config is a validated invocation. Every field is safe to act on: host, dir
// and expected are non-empty, and every fingerprint in expected is a
// well-formed SHA-256 fingerprint.
type config struct {
	host     string
	port     int
	owner    string
	dir      string
	expected map[string]bool
}

// run executes the whole provisioning workflow and returns a typed error
// instead of exiting, so every branch is reachable from a test.
//
// The order of the steps IS the security property, and it is deliberate:
// validate the invocation, capture the presented key, compare it against the
// operator's out-of-band fingerprints, and only then open the store. A key
// that matches nothing is rejected before any directory is created, any store
// is opened, and any existing pin is read or removed.
func run(ctx context.Context, args []string, d deps) error {
	cfg, err := parseArgs(args)
	if err != nil {
		return err
	}

	pub, err := d.capture(cfg.host, cfg.port)
	if err != nil {
		return &CaptureError{Host: cfg.host, Port: cfg.port, Err: err}
	}

	pin := knownhosts.PinFromPublicKey(cfg.host, sshscope.Service, cfg.owner, pub, "manual")

	// Fail closed before anything is opened or written: the key the target
	// presented has to be one the operator verified out of band.
	if !cfg.expected[pin.Fingerprint] {
		return &FingerprintMismatchError{
			Host:      cfg.host,
			Port:      cfg.port,
			Presented: pin.Fingerprint,
			Algorithm: pin.Algorithm,
			Expected:  sortedKeys(cfg.expected),
		}
	}

	store, err := d.openStore(cfg.dir)
	if err != nil {
		return &StoreError{Op: "open", Dir: cfg.dir, Err: err}
	}

	// Unreadable existing state aborts before any write. "Nothing is
	// recorded" and "what is recorded cannot be read" are different facts,
	// and only the first one licenses writing a pin.
	existing, xerr := existingPin(ctx, store, cfg.owner, cfg.host)
	if xerr != nil {
		return &StoreError{Op: "read existing pin", Dir: cfg.dir, Err: xerr}
	}
	if existing != nil {
		if existing.Fingerprint == pin.Fingerprint {
			// Discarded for the reason given on report: the pin is already
			// durable, and the exit status carries the outcome.
			_, _ = fmt.Fprintf(d.stdout, "already pinned: host=%s owner=%s %s %s\n", cfg.host, cfg.owner, pin.Algorithm, pin.Fingerprint)
			return nil
		}
		// Add never overwrites, so rotation is remove-then-add. Safe only
		// because the replacement matched an operator-asserted fingerprint
		// above, and because the record being replaced was read successfully
		// rather than assumed absent.
		if rerr := store.Remove(ctx, sshscope.Service, cfg.owner, cfg.host); rerr != nil {
			return &StoreError{Op: "rotate (remove stale pin)", Dir: cfg.dir, Err: rerr}
		}

		// Between the Remove above and the Add below the host has no pin, and
		// the Store interface offers no atomic replace to close that window.
		// If the replacement does not land, put the old one back: a failed
		// rotation must leave the host as it was, not unpinned. The deployer
		// is fail-closed, so an unpinned host cannot be deployed to at all —
		// dropping the record would turn a recoverable write failure into an
		// outage on that host, and the operator would have to re-run this
		// command just to get back to where they started.
		if aerr := store.Add(ctx, pin); aerr != nil {
			if rberr := store.Add(ctx, existing); rberr != nil {
				return &RotationRollbackError{
					Host:        cfg.host,
					Owner:       cfg.owner,
					Dir:         cfg.dir,
					Fingerprint: existing.Fingerprint,
					Err:         aerr,
					RollbackErr: rberr,
				}
			}
			return &StoreError{Op: "rotate (add replacement pin; the previous pin was restored)", Dir: cfg.dir, Err: aerr}
		}
		_, _ = fmt.Fprintf(d.stdout, "pinned: host=%s owner=%s scope=service %s %s\n", cfg.host, cfg.owner, pin.Algorithm, pin.Fingerprint)
		return nil
	}

	if err := store.Add(ctx, pin); err != nil {
		return &StoreError{Op: "add pin", Dir: cfg.dir, Err: err}
	}
	_, _ = fmt.Fprintf(d.stdout, "pinned: host=%s owner=%s scope=service %s %s\n", cfg.host, cfg.owner, pin.Algorithm, pin.Fingerprint)
	return nil
}

// existingPin returns the pin recorded for (service, owner, host), or nil when
// the store holds none.
//
// Absence and failure must not be confused: "nothing is recorded" licenses
// writing a pin, "the record could not be read" does not. The store reports
// absence, a corrupt envelope and a backend failure as three distinct error
// types, but the quicbaas SDK re-export carries none of them (only Store, Pin,
// PinFromPublicKey, NewBackendStore, ImportKnownHostsFile), and importing
// go-xkms directly is forbidden — pkg/arch/layerguard_test.go enforces it. So
// Get's error cannot be classified here, and treating every one of them as
// "absent" is exactly the bug this function exists to prevent.
//
// The resolution is to ask a question whose answer is unambiguous. List
// reports absence as an empty result and reserves its error for a genuine
// failure, so it separates the two cases without needing any error type.
//
// Get still runs first, and on the normal path it is the only call made: when
// the requested host's record reads cleanly, nothing else in the store is
// consulted and no other host can affect the outcome. List runs only to
// interpret a Get that already failed.
//
// Residual limitation: List scans the whole (service, owner) prefix, so when
// the requested host has NO record and some other host under the same owner
// has an unreadable one, the run aborts although the requested host was merely
// absent. That is fail-safe rather than fail-open, and it cannot be narrowed
// further from this side — it needs the SDK to re-export the knownhosts
// not-found error (or an IsNotFound helper), filed upstream as a go-quicbaas
// gap under doc 00 L8. Probing the backend for the record's raw storage key
// was considered and rejected: the key layout is unexported, and hard-coding
// it here would couple this command to a format that can change silently.
func existingPin(ctx context.Context, store knownhosts.Store, owner, host string) (*knownhosts.Pin, error) {
	pin, gerr := store.Get(ctx, sshscope.Service, owner, host)
	if gerr == nil {
		return pin, nil
	}

	pins, lerr := store.List(ctx, sshscope.Service, owner)
	if lerr != nil {
		return nil, lerr
	}
	for _, p := range pins {
		if p.Host == host {
			// A record for this host exists, and Get could not read it.
			// Report Get's own failure — it is the precise one.
			return nil, gerr
		}
	}
	return nil, nil
}

// parseArgs turns a command line into a validated config. It never dials and
// never touches the store: a missing or malformed flag has to fail here, with
// nothing provisioned and no connection made.
func parseArgs(args []string) (*config, error) {
	fs := flag.NewFlagSet("deployer-pin", flag.ContinueOnError)
	// Reporting is the caller's job (see report), so the flag package neither
	// prints nor exits.
	fs.SetOutput(io.Discard)
	var (
		host   = fs.String("host", "", "target host (IP or hostname) to pin")
		port   = fs.Int("port", 22, "target SSH port")
		owner  = fs.String("owner", "", "pin owner (defaults to --host)")
		dir    = fs.String("dir", "", "known_hosts store root directory (the directory containing known_hosts_path)")
		expect = fs.String("expect-fingerprint", "", "REQUIRED: comma-separated host key fingerprints obtained out of band (SHA256:... as printed by `ssh-keygen -lf`); a key matching none of them is never pinned")
	)
	if err := fs.Parse(args); err != nil {
		return nil, &UsageError{Reason: err.Error(), Err: err}
	}
	if *host == "" || *dir == "" || *expect == "" {
		return nil, &UsageError{Reason: "--host, --dir and --expect-fingerprint are all required"}
	}

	expected, err := parseFingerprints(*expect)
	if err != nil {
		return nil, err
	}

	ownerVal := *owner
	if ownerVal == "" {
		ownerVal = *host
	}
	return &config{host: *host, port: *port, owner: ownerVal, dir: *dir, expected: expected}, nil
}

// report writes the operator-facing diagnostic for err. Usage failures also
// get the full usage text, which names the out-of-band channels a fingerprint
// may come from; an explicit -h/--help gets that text on its own.
//
// The write errors are discarded deliberately, and this is the one place in
// the command where discarding an error is right. There is no second channel
// on which to report that the reporting channel failed, and the run's outcome
// does not depend on the message arriving: exitCode carries it independently,
// so a caller whose stderr is closed or full still learns what happened from
// the exit status. Acting on the failure would mean either aborting a run that
// has already finished, or inventing an exit code for "could not print", which
// would change a documented contract over a condition nobody can remedy.
//
// Note that writing these through fmt.Fprintf instead would silence errcheck
// via .golangci.yml's exclude-functions list without changing the behaviour
// one bit. That is not a fix, so the discard is written out where a reader can
// see and challenge it.
func report(err error, w io.Writer) {
	if err == nil {
		return
	}
	// An explicit help request gets the usage text alone — no error banner
	// above it, matching what `flag` itself prints for -h.
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.WriteString(w, usageText)
		return
	}
	_, _ = fmt.Fprintln(w, err)
	if isUsageError(err) {
		_, _ = io.WriteString(w, usageText)
	}
}

// exitCode maps a run error onto the process exit status: 2 for an invocation
// the operator has to correct, 1 for a failure against the target or the
// store, 0 for success.
func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		// -h/--help is a request that succeeded, not a malformed command
		// line. The standard Go help path (flag.ExitOnError) exits 0, and
		// scripts probe binaries with --help to test for availability.
		return 0
	case isUsageError(err):
		return 2
	default:
		return 1
	}
}

// isUsageError reports whether err says the command line itself is wrong,
// rather than the target or the store.
func isUsageError(err error) bool {
	var ue *UsageError
	var ife *InvalidFingerprintError
	return errors.As(err, &ue) || errors.As(err, &ife) || errors.Is(err, ErrNoFingerprints)
}

// openFileStore creates dir (0700, operator-only) and opens the file-backed pin
// store the deployer, switch driver and fabric driver read.
//
// The mode passed to MkdirAll only applies to a directory it CREATES; an
// existing directory keeps whatever permissions it already had. So the store
// root is checked explicitly afterwards. Pins hold no secret — a fingerprint
// is public — but they are integrity-critical: anyone who can write into this
// directory chooses which host key the whole fleet's install path trusts, and
// can do so after provisioning, silently. A store under a directory another
// principal can write is not a store worth checking a host key against.
func openFileStore(dir string) (knownhosts.Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := checkStoreDir(dir); err != nil {
		return nil, err
	}
	backend, err := filestorage.New(dir)
	if err != nil {
		return nil, err
	}
	return knownhosts.NewBackendStore(backend)
}

// checkStoreDir rejects a store root that someone other than its owner could
// tamper with.
//
// Only the store directory itself is checked, not its ancestors: a store under
// /etc (0755) or a test root under /tmp (1777) is normal and rejecting those
// would make the command unusable, while the leaf is the directory whose write
// permission decides who can add or replace a pin.
//
// Lstat, not Stat, because a symlinked store root is resolved by MkdirAll and
// by every subsequent write — whoever controls the link controls where the
// pins actually land, regardless of the target's own mode.
func checkStoreDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return &InsecureStoreDirError{Dir: dir, Reason: "is a symlink; whoever controls the link controls where pins are written"}
	}
	if !mode.IsDir() {
		return &InsecureStoreDirError{Dir: dir, Reason: "is not a directory"}
	}
	// Write access is the risk, not visibility. A fingerprint is public, so
	// group/other READ or EXECUTE bits give an attacker nothing — and the
	// standard layout, a root-owned 0755 /etc/platform/deployer, is exactly
	// that. Rejecting those bits would make the documented deployment
	// impossible without restructuring the config directory, to protect
	// against reading values that are published on the host's console.
	//
	// The sticky bit is NOT an exemption here, unlike for the ancestors: on a
	// directory this command writes into, the attack is creating or replacing
	// a pin FILE, and sticky only restricts deleting or renaming entries that
	// already belong to someone else. A sticky world-writable store still lets
	// anyone drop in a pin for a host that has none yet.
	if perm := mode.Perm(); perm&0o022 != 0 {
		return &InsecureStoreDirError{
			Dir:    dir,
			Reason: "has mode " + fs.FileMode(perm).String() + ", which lets others write pins into it; run `chmod go-w " + dir + "`",
		}
	}
	// A directory owned by someone else is under their control even at 0700 —
	// and when this command runs as root the mode alone would not stop them.
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if uid := os.Getuid(); int(st.Uid) != uid {
			return &InsecureStoreDirError{
				Dir:    dir,
				Reason: "is owned by uid " + strconv.FormatUint(uint64(st.Uid), 10) + ", not by the invoking user (uid " + strconv.Itoa(uid) + ")",
			}
		}
	}
	return checkStoreAncestors(dir, os.Getuid())
}

// checkStoreAncestors rejects a store path that another principal could
// redirect by swapping a directory above it.
//
// Locking down the leaf is not enough on its own: if any ancestor is writable
// by others, or belongs to someone else, they can rename the checked directory
// aside and put their own in its place — before the first write or long after
// the last one — and the deployer then verifies host keys against a store they
// control. The leaf's own 0700 says nothing about that.
//
// The walk runs over the RESOLVED path. Lstat on an unresolved component
// reports a symlink's own mode, which POSIX ignores and which is always 0777,
// so walking the literal path would reject any store beneath a standard
// symlinked directory — /var/run, a symlink to /run on most Linux systems, is
// the common case. What matters is the real directory the name resolves to.
//
// Two rules apply to each resolved component:
//
//   - Not writable by group or others, UNLESS sticky. The sticky bit is the
//     subtlety: on a sticky directory (/tmp, mode 1777) a user may unlink or
//     rename only entries they own, so the swap is not available. Ignoring it
//     would reject every store under /tmp — including every test here — for no
//     gain, and a check that fires spuriously is a check that gets switched off.
//   - Owned by root or by the invoking user. Mode alone misses the case that
//     matters most when this runs as root: /home/alice at 0755 is not writable
//     by "others" in the mode sense, yet alice can rename anything directly
//     inside it. Root is allowed because the system directories every path
//     runs through — /, /etc, /var — belong to root, and requiring the
//     invoking user to own them would reject every path on the machine.
//
// uid is a parameter rather than a call to os.Getuid so the walk can be
// exercised against an ancestor the invoking user does not own — the
// /home/alice case — which otherwise needs root to set up.
func checkStoreAncestors(dir string, uid int) error {
	return checkStoreAncestorsWith(dir, uid, os.Lstat)
}

// checkStoreAncestorsWith is checkStoreAncestors with the directory stat
// indirected.
//
// The indirection exists for one reason and it is not stylistic: the
// ownership arm of this walk rejects an ancestor owned by neither root nor
// the invoking user, and that condition CANNOT be built out of real
// directories on every host the suite runs on. Creating a directory owned by
// a third user requires root, and when the suite DOES run as root — which it
// does in CI — every directory it creates is root-owned, which this function
// deliberately allows. So a test that builds real directories asserts the
// rejection on a workstation and silently asserts nothing under CI. Measured
// 2026-09-03: TestCheckStoreAncestorsRejectsAncestorOwnedByAnotherUser passed
// locally as uid 1000 and failed in CI as uid 0 for exactly that reason.
//
// Production always passes os.Lstat; only tests substitute anything else.
func checkStoreAncestorsWith(dir string, uid int, lstat func(string) (fs.FileInfo, error)) error {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	for path := filepath.Dir(resolved); ; path = filepath.Dir(path) {
		info, serr := lstat(path)
		if serr != nil {
			return serr
		}
		perm := info.Mode().Perm()
		if perm&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return &InsecureStoreDirError{
				Dir: dir,
				Reason: "sits under " + strconv.Quote(path) + ", which is mode " + fs.FileMode(perm).String() +
					" — writable by others and not sticky, so they can replace the store directory itself",
			}
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && !ancestorOwnerAllowed(st.Uid, uid) {
			return &InsecureStoreDirError{
				Dir: dir,
				Reason: "sits under " + strconv.Quote(path) + ", which is owned by uid " +
					strconv.FormatUint(uint64(st.Uid), 10) + " — neither root nor the invoking user (uid " +
					strconv.Itoa(uid) + "), who can therefore replace the store directory",
			}
		}
		if path == filepath.Dir(path) { // reached the root
			return nil
		}
	}
}

// ancestorOwnerAllowed reports whether a directory owned by owner may appear
// above the pin store when the command runs as uid. Root is allowed because
// every path traverses root-owned system directories; the invoking user is
// allowed because they already control their own tree. Anyone else can rename
// the store aside, so they are not.
func ancestorOwnerAllowed(owner uint32, uid int) bool {
	return owner == 0 || int(owner) == uid
}

// InsecureStoreDirError reports a pin-store root that cannot be trusted to
// hold host-key envelopes. Reason says which rule failed and, where there is
// one, the command that fixes it.
type InsecureStoreDirError struct {
	Dir    string
	Reason string
}

// Error implements the error interface.
func (e *InsecureStoreDirError) Error() string {
	return "deployer-pin: refusing to use pin store " + strconv.Quote(e.Dir) + ": it " + e.Reason
}

// captureHostKey dials the target with the Go x/crypto/ssh handshake and
// returns the host key the server presents. Authentication is never attempted;
// the host-key callback fires during key exchange, captures the key, and
// aborts the handshake.
func captureHostKey(host string, port int) (ssh.PublicKey, error) {
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return errCaptured
		},
		Timeout: 10 * time.Second,
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	_, derr := ssh.Dial("tcp", addr, cfg)
	if captured != nil {
		return captured, nil
	}
	return nil, &NoHostKeyError{Err: derr}
}

// UsageError reports a command line that cannot be acted on — a flag the
// parser rejected, or a mandatory flag left off. It is distinct from a
// fingerprint that is present but malformed (InvalidFingerprintError) so the
// caller classifies by type rather than by message text.
type UsageError struct {
	Reason string
	Err    error
}

// Error implements the error interface.
func (e *UsageError) Error() string { return "deployer-pin: " + e.Reason }

// Unwrap exposes the flag package's own error, when there was one.
func (e *UsageError) Unwrap() error { return e.Err }

// FingerprintMismatchError reports the fail-closed rejection this command
// exists to perform: the target presented a key matching none of the
// fingerprints the operator obtained out of band, so nothing was pinned. It
// carries the presented and expected values because the operator's next step
// depends on which side is wrong.
type FingerprintMismatchError struct {
	Host      string
	Port      int
	Presented string
	Algorithm string
	Expected  []string
}

// Error implements the error interface.
func (e *FingerprintMismatchError) Error() string {
	return "deployer-pin: host key MISMATCH for " + net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) + " — nothing was pinned\n" +
		"  presented: " + e.Presented + " (" + e.Algorithm + ")\n" +
		"  expected one of: " + strings.Join(e.Expected, ", ")
}

// CaptureError reports a failure to obtain the target's host key at all — the
// dial never reached key exchange, or the target is unreachable.
type CaptureError struct {
	Host string
	Port int
	Err  error
}

// Error implements the error interface.
func (e *CaptureError) Error() string {
	return "deployer-pin: capture host key from " + net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) + ": " + e.Err.Error()
}

// Unwrap exposes the underlying dial failure.
func (e *CaptureError) Unwrap() error { return e.Err }

// NoHostKeyError reports a handshake that ended without the host-key callback
// ever firing, so there was no key to compare.
type NoHostKeyError struct {
	Err error
}

// Error implements the error interface.
func (e *NoHostKeyError) Error() string {
	if e.Err == nil {
		return "no host key captured"
	}
	return "no host key captured: " + e.Err.Error()
}

// Unwrap exposes the underlying dial failure.
func (e *NoHostKeyError) Unwrap() error { return e.Err }

// StoreError reports a failure in the pin store. Op names the operation that
// failed so the operator can tell "the store could not be opened" from "the
// stale pin could not be removed" — the second leaves the host unpinned, the
// first leaves it exactly as it was.
type StoreError struct {
	Op  string
	Dir string
	Err error
}

// Error implements the error interface.
func (e *StoreError) Error() string {
	return "deployer-pin: " + e.Op + " (" + e.Dir + "): " + e.Err.Error()
}

// Unwrap exposes the underlying store failure.
func (e *StoreError) Unwrap() error { return e.Err }

// RotationRollbackError reports the one outcome this command must never leave
// silently: the stale pin was removed, the replacement could not be written,
// AND the stale pin could not be put back — so the host is now unpinned. The
// deployer is fail-closed, so that host cannot be deployed to until a pin is
// provisioned again. It is a distinct type from StoreError because the
// operator's next step is different and urgent: re-run this command against
// the host rather than merely retry a write.
type RotationRollbackError struct {
	Host        string
	Owner       string
	Dir         string
	Fingerprint string
	Err         error
	RollbackErr error
}

// Error implements the error interface.
func (e *RotationRollbackError) Error() string {
	return "deployer-pin: rotation FAILED and the previous pin could not be restored — " +
		e.Host + " (owner " + e.Owner + ") is now UNPINNED in " + e.Dir + " and cannot be deployed to until re-pinned\n" +
		"  writing the replacement failed: " + e.Err.Error() + "\n" +
		"  restoring " + e.Fingerprint + " failed: " + e.RollbackErr.Error()
}

// Unwrap returns the failure that caused the rotation to fail. The rollback
// failure is reachable through the RollbackErr field.
func (e *RotationRollbackError) Unwrap() error { return e.Err }

// InvalidFingerprintError reports an --expect-fingerprint entry that is not a
// SHA-256 fingerprint. Value is the offending entry and Reason says how it is
// malformed, so a caller classifies the failure by type rather than by
// matching on message text (AGENTS.md, conventions/errors.md §2: no new
// fmt.Errorf under cmd/).
type InvalidFingerprintError struct {
	Value  string
	Reason string
}

// Error implements the error interface.
func (e *InvalidFingerprintError) Error() string {
	return "deployer-pin: invalid --expect-fingerprint " + strconv.Quote(e.Value) + ": " + e.Reason
}

// ErrNoFingerprints reports an --expect-fingerprint value that held no entries
// at all, such as "" or ",,".
var ErrNoFingerprints = errors.New("deployer-pin: --expect-fingerprint contained no fingerprints")

// parseFingerprints splits the --expect-fingerprint value into a set.
//
// Every entry has to be a real SHA-256 fingerprint, not merely SHA256:-
// prefixed. A malformed entry that reached the set would match no key, so the
// run would dial the target and report a host-key MISMATCH — blaming the
// target for a typo in the operator's own command line, which is the opposite
// of the fail-fast the flag exists to give. ssh.FingerprintSHA256 emits
// RawStdEncoding over a SHA-256 digest, so the body must decode, unpadded, to
// exactly sha256.Size bytes.
func parseFingerprints(v string) (map[string]bool, error) {
	set := make(map[string]bool)
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		body, ok := strings.CutPrefix(f, "SHA256:")
		if !ok {
			return nil, &InvalidFingerprintError{Value: f, Reason: "missing SHA256: prefix (expected SHA256:<base64>, as `ssh-keygen -lf` prints)"}
		}
		if body == "" {
			return nil, &InvalidFingerprintError{Value: f, Reason: "empty body"}
		}
		digest, derr := base64.RawStdEncoding.DecodeString(body)
		if derr != nil {
			return nil, &InvalidFingerprintError{Value: f, Reason: "body is not raw (unpadded) base64"}
		}
		if len(digest) != sha256.Size {
			return nil, &InvalidFingerprintError{
				Value:  f,
				Reason: "body decodes to " + strconv.Itoa(len(digest)) + " bytes, want " + strconv.Itoa(sha256.Size) + " for SHA-256",
			}
		}
		set[f] = true
	}
	if len(set) == 0 {
		return nil, ErrNoFingerprints
	}
	return set, nil
}

// sortedKeys returns the set's keys in a stable order for diagnostics.
func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
