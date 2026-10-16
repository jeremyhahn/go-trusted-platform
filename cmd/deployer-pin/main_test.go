package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	knownhosts "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/knownhosts"
	sshscope "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/scope"
	"golang.org/x/crypto/ssh"
)

// newHostKey returns a freshly generated SSH host public key and its
// fingerprint in the form --expect-fingerprint takes. Ed25519 keygen is a
// few microseconds, so every test gets real keys rather than fixtures.
func newHostKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh signer: %v", err)
	}
	pub := signer.PublicKey()
	return pub, ssh.FingerprintSHA256(pub)
}

// countingStore wraps the real file-backed pin store and counts the two
// mutating operations. The store underneath is production code operating on a
// real directory — the counters only observe it, so "zero mutations" means the
// store was genuinely never asked to change anything.
type countingStore struct {
	knownhosts.Store
	adds    int
	removes int
}

func (s *countingStore) Add(ctx context.Context, pin *knownhosts.Pin) error {
	s.adds++
	return s.Store.Add(ctx, pin)
}

func (s *countingStore) Remove(ctx context.Context, sc sshscope.Scope, owner, host string) error {
	s.removes++
	return s.Store.Remove(ctx, sc, owner, host)
}

// harness holds one test's injected dependencies and the evidence they
// collect: whether the target was dialed, whether the store was opened, and
// how many times it was mutated.
type harness struct {
	dir      string
	dials    int
	opens    int
	store    *countingStore
	stdout   strings.Builder
	presents ssh.PublicKey
	dialErr  error
	openErr  error
}

// privateTempDir returns a temp directory whose whole chain below the system
// temp root is 0700.
//
// t.TempDir() honours the umask, so it typically yields group-writable (0775)
// directories. A real pin store lives on a path no other principal can write —
// that is precisely what checkStoreDir enforces — so a test that used the
// default would be exercising a path the command is right to refuse, and every
// rejection test would risk passing for the wrong reason.
func privateTempDir(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	root := os.TempDir()
	for p := base; p != root && p != "/" && p != filepath.Dir(p); p = filepath.Dir(p) {
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
	return base
}

// newHarness builds a harness whose store is the real file-backed store rooted
// in a fresh temp directory, opened lazily exactly as production does.
func newHarness(t *testing.T, presents ssh.PublicKey) *harness {
	t.Helper()
	// The store directory is deliberately a path that does not exist yet, so
	// a test can assert that a rejected key never brought it into being.
	return &harness{dir: filepath.Join(privateTempDir(t), "known_hosts.d"), presents: presents}
}

func (h *harness) deps() deps {
	return deps{
		capture: func(string, int) (ssh.PublicKey, error) {
			h.dials++
			if h.dialErr != nil {
				return nil, h.dialErr
			}
			return h.presents, nil
		},
		openStore: func(dir string) (knownhosts.Store, error) {
			h.opens++
			if h.openErr != nil {
				return nil, h.openErr
			}
			if h.store == nil {
				inner, err := openFileStore(dir)
				if err != nil {
					return nil, err
				}
				h.store = &countingStore{Store: inner}
			}
			return h.store, nil
		},
		stdout: &h.stdout,
	}
}

// args builds a command line for the harness's store directory.
func (h *harness) args(host, expect string) []string {
	return []string{"--host", host, "--dir", h.dir, "--expect-fingerprint", expect}
}

// pinned reads the pin recorded for host straight out of the store directory,
// bypassing the harness counters.
func (h *harness) pinned(t *testing.T, host string) *knownhosts.Pin {
	t.Helper()
	store, err := openFileStore(h.dir)
	if err != nil {
		t.Fatalf("open store for readback: %v", err)
	}
	pin, err := store.Get(context.Background(), sshscope.Service, host, host)
	if err != nil {
		return nil
	}
	return pin
}

// pinned2 reads the pin for an explicit owner, for the shared-owner cases.
func (h *harness) pinned2(t *testing.T, owner, host string) *knownhosts.Pin {
	t.Helper()
	store, err := openFileStore(h.dir)
	if err != nil {
		t.Fatalf("open store for readback: %v", err)
	}
	pin, err := store.Get(context.Background(), sshscope.Service, owner, host)
	if err != nil {
		return nil
	}
	return pin
}

func (h *harness) mutations() (adds, removes int) {
	if h.store == nil {
		return 0, 0
	}
	return h.store.adds, h.store.removes
}

// TestRun_MatchPersistsPin is the accepting half of the gate: a presented key
// whose fingerprint the operator asserted out of band is pinned, under the
// scope and owner the deployer resolves at connect time.
func TestRun_MatchPersistsPin(t *testing.T) {
	pub, fp := newHostKey(t)
	h := newHarness(t, pub)

	if err := run(context.Background(), h.args("10.0.0.7", fp), h.deps()); err != nil {
		t.Fatalf("run: %v", err)
	}

	pin := h.pinned(t, "10.0.0.7")
	if pin == nil {
		t.Fatal("no pin was persisted for a key that matched the expected fingerprint")
	}
	if pin.Fingerprint != fp {
		t.Errorf("pin.Fingerprint = %q, want %q", pin.Fingerprint, fp)
	}
	if pin.Algorithm != pub.Type() {
		t.Errorf("pin.Algorithm = %q, want %q", pin.Algorithm, pub.Type())
	}
	if pin.Scope != sshscope.Service || pin.Owner != "10.0.0.7" {
		t.Errorf("pin scope/owner = %v/%q, want service/%q", pin.Scope, pin.Owner, "10.0.0.7")
	}
	if adds, removes := h.mutations(); adds != 1 || removes != 0 {
		t.Errorf("store mutations = %d adds / %d removes, want 1/0", adds, removes)
	}
	if !strings.Contains(h.stdout.String(), "pinned: host=10.0.0.7") {
		t.Errorf("stdout = %q, want the pinned status line", h.stdout.String())
	}
}

// TestRun_MismatchRejectsBeforeTouchingStore is the reason this command
// exists. A machine-in-the-middle presenting its own key must be rejected
// before the store is even opened — not written and then rolled back, and not
// written at all.
func TestRun_MismatchRejectsBeforeTouchingStore(t *testing.T) {
	presented, _ := newHostKey(t)
	_, expectedFP := newHostKey(t) // the key the operator actually verified
	h := newHarness(t, presented)

	err := run(context.Background(), h.args("10.0.0.7", expectedFP), h.deps())

	var mismatch *FingerprintMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("run: got %v (%T), want *FingerprintMismatchError", err, err)
	}
	if mismatch.Presented != ssh.FingerprintSHA256(presented) {
		t.Errorf("error reports presented %q, want %q", mismatch.Presented, ssh.FingerprintSHA256(presented))
	}
	if len(mismatch.Expected) != 1 || mismatch.Expected[0] != expectedFP {
		t.Errorf("error reports expected %v, want [%s]", mismatch.Expected, expectedFP)
	}
	if h.opens != 0 {
		t.Errorf("store was opened %d times on a rejected key, want 0", h.opens)
	}
	if adds, removes := h.mutations(); adds != 0 || removes != 0 {
		t.Errorf("store mutations = %d adds / %d removes on a rejected key, want 0/0", adds, removes)
	}
	if _, statErr := os.Stat(h.dir); !os.IsNotExist(statErr) {
		t.Errorf("store directory %s exists after a rejected key; it must never be created", h.dir)
	}
	if exitCode(err) != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode(err))
	}
}

// TestRun_ExistingPinPreservedAfterRejection covers the state that matters
// most operationally: a host already correctly pinned, then probed again while
// something else answers. The good pin must survive untouched.
func TestRun_ExistingPinPreservedAfterRejection(t *testing.T) {
	good, goodFP := newHostKey(t)
	h := newHarness(t, good)
	if err := run(context.Background(), h.args("10.0.0.7", goodFP), h.deps()); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	adds, removes := h.mutations()

	// Now an impostor answers, while the operator still expects the real key.
	impostor, _ := newHostKey(t)
	h.presents = impostor
	err := run(context.Background(), h.args("10.0.0.7", goodFP), h.deps())

	var mismatch *FingerprintMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("run: got %v (%T), want *FingerprintMismatchError", err, err)
	}
	if newAdds, newRemoves := h.mutations(); newAdds != adds || newRemoves != removes {
		t.Errorf("store mutated during rejection: adds %d->%d, removes %d->%d", adds, newAdds, removes, newRemoves)
	}
	pin := h.pinned(t, "10.0.0.7")
	if pin == nil || pin.Fingerprint != goodFP {
		t.Fatalf("existing pin = %v, want the original %s preserved", pin, goodFP)
	}
}

// TestRun_RotatesOnlyAfterVerifiedReplacement covers a legitimate key
// rotation: the operator re-runs with the NEW fingerprint they verified out of
// band, and the stale pin is replaced exactly once.
func TestRun_RotatesOnlyAfterVerifiedReplacement(t *testing.T) {
	old, oldFP := newHostKey(t)
	h := newHarness(t, old)
	if err := run(context.Background(), h.args("10.0.0.7", oldFP), h.deps()); err != nil {
		t.Fatalf("seed run: %v", err)
	}

	replacement, replacementFP := newHostKey(t)
	h.presents = replacement
	if err := run(context.Background(), h.args("10.0.0.7", replacementFP), h.deps()); err != nil {
		t.Fatalf("rotate run: %v", err)
	}

	pin := h.pinned(t, "10.0.0.7")
	if pin == nil || pin.Fingerprint != replacementFP {
		t.Fatalf("pin = %v, want the rotated fingerprint %s", pin, replacementFP)
	}
	if adds, removes := h.mutations(); adds != 2 || removes != 1 {
		t.Errorf("store mutations = %d adds / %d removes, want 2/1 (seed add, rotate remove+add)", adds, removes)
	}
}

// TestRun_AlreadyPinnedIsIdempotent: re-running against an unchanged host must
// leave the store alone rather than churn a remove/add pair.
func TestRun_AlreadyPinnedIsIdempotent(t *testing.T) {
	pub, fp := newHostKey(t)
	h := newHarness(t, pub)
	if err := run(context.Background(), h.args("10.0.0.7", fp), h.deps()); err != nil {
		t.Fatalf("seed run: %v", err)
	}

	h.stdout.Reset()
	if err := run(context.Background(), h.args("10.0.0.7", fp), h.deps()); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if adds, removes := h.mutations(); adds != 1 || removes != 0 {
		t.Errorf("store mutations = %d adds / %d removes, want 1/0 (the seed add only)", adds, removes)
	}
	if !strings.Contains(h.stdout.String(), "already pinned") {
		t.Errorf("stdout = %q, want the already-pinned status line", h.stdout.String())
	}
}

// TestRun_MandatoryFlagsFailBeforeDialing pins the ordering the fail-closed
// design depends on: an invocation the operator has to fix is rejected before
// the target is contacted and before the store is opened. An omitted
// --expect-fingerprint in particular must never degrade to trust-on-first-use.
func TestRun_MandatoryFlagsFailBeforeDialing(t *testing.T) {
	_, fp := newHostKey(t)
	for name, args := range map[string][]string{
		"no expect-fingerprint": {"--host", "10.0.0.7", "--dir", "/store"},
		"no host":               {"--dir", "/store", "--expect-fingerprint", fp},
		"no dir":                {"--host", "10.0.0.7", "--expect-fingerprint", fp},
		"empty expect value":    {"--host", "10.0.0.7", "--dir", "/store", "--expect-fingerprint", ""},
		"unknown flag":          {"--host", "10.0.0.7", "--dir", "/store", "--expect-fingerprint", fp, "--trust-on-first-use"},
		"bad port":              {"--host", "10.0.0.7", "--dir", "/store", "--expect-fingerprint", fp, "--port", "ssh"},
	} {
		t.Run(name, func(t *testing.T) {
			pub, _ := newHostKey(t)
			h := newHarness(t, pub)
			err := run(context.Background(), args, h.deps())

			// Any of the invocation-error types is a correct outcome; what
			// must never happen is the run proceeding to dial or write.
			if !isUsageError(err) {
				t.Fatalf("run: got %v (%T), want an invocation error", err, err)
			}
			if h.dials != 0 {
				t.Errorf("target was dialed %d times on a bad command line, want 0", h.dials)
			}
			if h.opens != 0 {
				t.Errorf("store was opened %d times on a bad command line, want 0", h.opens)
			}
			if exitCode(err) != 2 {
				t.Errorf("exitCode = %d, want 2", exitCode(err))
			}
		})
	}
}

// TestRun_MalformedFingerprintFailsBeforeDialing: a typo in the operator's own
// fingerprint must be reported as such, not surfaced later as a host-key
// mismatch that blames the target.
func TestRun_MalformedFingerprintFailsBeforeDialing(t *testing.T) {
	pub, _ := newHostKey(t)
	h := newHarness(t, pub)

	err := run(context.Background(), h.args("10.0.0.7", "SHA256:not-a-real-key"), h.deps())

	var ife *InvalidFingerprintError
	if !errors.As(err, &ife) {
		t.Fatalf("run: got %v (%T), want *InvalidFingerprintError", err, err)
	}
	if h.dials != 0 || h.opens != 0 {
		t.Errorf("dials=%d opens=%d on a malformed fingerprint, want 0/0", h.dials, h.opens)
	}
	if exitCode(err) != 2 {
		t.Errorf("exitCode = %d, want 2", exitCode(err))
	}
}

// TestRun_CaptureFailureLeavesStoreUntouched: an unreachable target is a
// failure to provision, never a reason to write something.
func TestRun_CaptureFailureLeavesStoreUntouched(t *testing.T) {
	_, fp := newHostKey(t)
	h := newHarness(t, nil)
	h.dialErr = &NoHostKeyError{Err: errors.New("connection refused")}

	err := run(context.Background(), h.args("10.0.0.7", fp), h.deps())

	var ce *CaptureError
	if !errors.As(err, &ce) {
		t.Fatalf("run: got %v (%T), want *CaptureError", err, err)
	}
	var nhk *NoHostKeyError
	if !errors.As(err, &nhk) {
		t.Errorf("CaptureError does not unwrap to the dial failure: %v", err)
	}
	if h.opens != 0 {
		t.Errorf("store was opened %d times after a failed capture, want 0", h.opens)
	}
	if exitCode(err) != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode(err))
	}
}

// TestRun_StoreOpenFailureIsReportedTyped: the store failing to open is a
// runtime failure (exit 1), distinguishable by type from a bad command line.
func TestRun_StoreOpenFailureIsReportedTyped(t *testing.T) {
	pub, fp := newHostKey(t)
	h := newHarness(t, pub)
	h.openErr = errors.New("permission denied")

	err := run(context.Background(), h.args("10.0.0.7", fp), h.deps())

	var se *StoreError
	if !errors.As(err, &se) {
		t.Fatalf("run: got %v (%T), want *StoreError", err, err)
	}
	if se.Op != "open" || se.Dir != h.dir {
		t.Errorf("StoreError{Op:%q, Dir:%q}, want {open, %s}", se.Op, se.Dir, h.dir)
	}
	if exitCode(err) != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode(err))
	}
}

// TestRun_OwnerDefaultsToHostAndIsOverridable: the pin is resolved by
// (scope, owner, host), so the owner the tool writes has to be the one the
// deployer looks up.
func TestRun_OwnerDefaultsToHostAndIsOverridable(t *testing.T) {
	pub, fp := newHostKey(t)
	h := newHarness(t, pub)
	args := []string{"--host", "10.0.0.7", "--owner", "bootstrap", "--dir", h.dir, "--expect-fingerprint", fp}
	if err := run(context.Background(), args, h.deps()); err != nil {
		t.Fatalf("run: %v", err)
	}

	store, err := openFileStore(h.dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, gerr := store.Get(context.Background(), sshscope.Service, "bootstrap", "10.0.0.7"); gerr != nil {
		t.Fatalf("no pin under the explicit owner: %v", gerr)
	}
	if _, gerr := store.Get(context.Background(), sshscope.Service, "10.0.0.7", "10.0.0.7"); gerr == nil {
		t.Error("a pin was also written under the default owner; --owner must replace it, not add to it")
	}
}

// TestExitCodeAndReport covers the main-level mapping in both directions: the
// code the process returns, and whether the usage text (which names the
// out-of-band channels a fingerprint may come from) is printed.
func TestExitCodeAndReport(t *testing.T) {
	for name, tc := range map[string]struct {
		err       error
		wantCode  int
		wantUsage bool
	}{
		"success":              {nil, 0, false},
		"usage":                {&UsageError{Reason: "missing flags"}, 2, true},
		"malformed print":      {&InvalidFingerprintError{Value: "x", Reason: "bad"}, 2, true},
		"no fingerprints":      {ErrNoFingerprints, 2, true},
		"mismatch":             {&FingerprintMismatchError{Host: "h", Port: 22, Presented: "SHA256:a"}, 1, false},
		"capture":              {&CaptureError{Host: "h", Port: 22, Err: errors.New("refused")}, 1, false},
		"store":                {&StoreError{Op: "add pin", Dir: "/d", Err: errors.New("full")}, 1, false},
		"wrapped usage":        {errWrap{&UsageError{Reason: "r"}}, 2, true},
		"help request":         {&UsageError{Reason: "flag: help requested", Err: flag.ErrHelp}, 0, true},
		"unclassified failure": {errors.New("something else"), 1, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := exitCode(tc.err); got != tc.wantCode {
				t.Errorf("exitCode = %d, want %d", got, tc.wantCode)
			}
			var out strings.Builder
			report(tc.err, &out)
			if tc.err == nil {
				if out.Len() != 0 {
					t.Errorf("report wrote %q for a nil error", out.String())
				}
				return
			}
			// A help request is the one error value that must NOT be echoed:
			// it is a successful request for the usage text, not a fault.
			if errors.Is(tc.err, flag.ErrHelp) {
				if strings.Contains(out.String(), tc.err.Error()) {
					t.Errorf("report echoed the help sentinel as an error:\n%s", out.String())
				}
			} else if !strings.Contains(out.String(), tc.err.Error()) {
				t.Errorf("report = %q, want it to contain %q", out.String(), tc.err.Error())
			}
			if gotUsage := strings.Contains(out.String(), "no trust-on-first-use path"); gotUsage != tc.wantUsage {
				t.Errorf("usage text printed = %v, want %v", gotUsage, tc.wantUsage)
			}
		})
	}
}

// errWrap proves the classification survives wrapping, since callers may add
// context to an error before it reaches exitCode.
type errWrap struct{ err error }

func (e errWrap) Error() string { return "context: " + e.err.Error() }
func (e errWrap) Unwrap() error { return e.err }

// TestCaptureHostKeyUnreachableTarget: a target that never answers yields a
// typed NoHostKeyError rather than a nil key and a nil error. Port 0 is never
// listening, so this dials nothing real and returns immediately.
func TestCaptureHostKeyUnreachableTarget(t *testing.T) {
	pub, err := captureHostKey("127.0.0.1", 0)
	if pub != nil {
		t.Errorf("captured a key from an unreachable target: %v", pub)
	}
	var nhk *NoHostKeyError
	if !errors.As(err, &nhk) {
		t.Fatalf("got %v (%T), want *NoHostKeyError", err, err)
	}
	if nhk.Unwrap() == nil {
		t.Error("NoHostKeyError carries no underlying dial failure")
	}
}

// TestOpenFileStoreCreatesDirectoryPrivate: the store root is operator-only.
// Pins carry no secret, but a world-writable pin store is a way to install a
// trusted key, which is exactly what this command refuses to do over SSH.
func TestOpenFileStoreCreatesDirectoryPrivate(t *testing.T) {
	dir := filepath.Join(privateTempDir(t), "nested", "known_hosts.d")
	store, err := openFileStore(dir)
	if err != nil {
		t.Fatalf("openFileStore: %v", err)
	}
	if store == nil {
		t.Fatal("openFileStore returned a nil store and no error")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat store dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("store dir mode = %o, want 700", perm)
	}
}

// TestOpenFileStoreRejectsNonDirectory: pointing --dir at a regular file has
// to fail, not silently provision somewhere else.
func TestOpenFileStoreRejectsNonDirectory(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "not-a-dir")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := openFileStore(filepath.Join(path, "store")); err == nil {
		t.Fatal("openFileStore succeeded under a regular file, want an error")
	}
}

// TestParseArgsDefaults covers the values a valid command line takes on when
// the optional flags are left off.
func TestParseArgsDefaults(t *testing.T) {
	_, fp := newHostKey(t)
	cfg, err := parseArgs([]string{"--host", "10.0.0.7", "--dir", "/store", "--expect-fingerprint", fp})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.port != 22 {
		t.Errorf("cfg.port = %d, want 22", cfg.port)
	}
	if cfg.owner != "10.0.0.7" {
		t.Errorf("cfg.owner = %q, want it to default to --host", cfg.owner)
	}
	if !cfg.expected[fp] || len(cfg.expected) != 1 {
		t.Errorf("cfg.expected = %v, want exactly {%s}", cfg.expected, fp)
	}
}

// TestParseFingerprints_RejectsNonSHA256 pins the reason the prefix check
// exists: a value that is not a SHA256 fingerprint must fail at parse time.
// Accepting it would build a set that can never match, which surfaces to the
// operator as a host-key mismatch — pointing at the target instead of at the
// typo in their own command line.
func TestParseFingerprints_RejectsNonSHA256(t *testing.T) {
	for _, v := range []string{
		"MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48",
		"256 SHA256:abc root@host (ED25519)", // a whole `ssh-keygen -lf` line
		"abc",
		// The prefix alone is not the check: a well-formed prefix over a
		// malformed body must fail here, not surface later as a host-key
		// mismatch that blames the target for the operator's typo.
		"SHA256:",
		"SHA256:not-a-real-key",
		"SHA256:fLn1MnrPUcV0cf5DApx1D+XujH5WF1i1klwGQfSu0/4=",  // padded
		"SHA256:fLn1MnrPUcV0cf5DApx1D+XujH5WF1i1klwGQfSu0",     // 31 bytes
		"SHA256:fLn1MnrPUcV0cf5DApx1D+XujH5WF1i1klwGQfSu0/4AA", // 33 bytes
		"SHA256:fLn1MnrPUcV0cf5DApx1D_XujH5WF1i1klwGQfSu0_4",   // URL alphabet
	} {
		_, err := parseFingerprints(v)
		if err == nil {
			t.Errorf("parseFingerprints(%q): want error, got nil", v)
			continue
		}
		// Classification is by type, not by message text.
		var ife *InvalidFingerprintError
		if !errors.As(err, &ife) {
			t.Errorf("parseFingerprints(%q): got %T, want *InvalidFingerprintError", v, err)
			continue
		}
		if ife.Value != v || ife.Reason == "" {
			t.Errorf("parseFingerprints(%q): error carries Value=%q Reason=%q", v, ife.Value, ife.Reason)
		}
	}
}

// TestParseFingerprints_Empty covers the values that hold no entry at all.
// These are a distinct condition from a malformed entry — nothing was given,
// rather than something wrong was — and report the declared sentinel.
func TestParseFingerprints_Empty(t *testing.T) {
	for _, v := range []string{"", ",,", "   ", " , "} {
		_, err := parseFingerprints(v)
		if !errors.Is(err, ErrNoFingerprints) {
			t.Errorf("parseFingerprints(%q): got %v, want ErrNoFingerprints", v, err)
		}
	}
}

func TestParseFingerprints_SetAndTrimming(t *testing.T) {
	const (
		a = "SHA256:fLn1MnrPUcV0cf5DApx1D+XujH5WF1i1klwGQfSu0/4"
		b = "SHA256:U7F3UHbTtO/JumeOOq2eY+WBi4jaPblZC5qtucsRjFM"
	)
	set, err := parseFingerprints("  " + a + " , " + b + " ,")
	if err != nil {
		t.Fatalf("parseFingerprints: %v", err)
	}
	if len(set) != 2 || !set[a] || !set[b] {
		t.Fatalf("set = %v, want exactly {%s, %s}", set, a, b)
	}
	// The property the pin gate relies on: an unlisted fingerprint is absent,
	// so !expected[fp] rejects it.
	if set["SHA256:b9XagUYPP8w3Syd0Hk37d1IolwzWRB39+xWr6ABiAvM"] {
		t.Fatal("unlisted fingerprint reported as expected")
	}
	if got := strings.Join(sortedKeys(set), ","); got != b+","+a && got != a+","+b {
		t.Fatalf("sortedKeys returned %q, want both fingerprints", got)
	}
}

// TestRun_AnyExpectedFingerprintMatches: the operator passes every key the
// host holds because the handshake, not the operator, picks which one is
// negotiated. Whichever of them is presented must be accepted.
func TestRun_AnyExpectedFingerprintMatches(t *testing.T) {
	first, firstFP := newHostKey(t)
	_, secondFP := newHostKey(t)
	h := newHarness(t, first)

	if err := run(context.Background(), h.args("10.0.0.7", secondFP+","+firstFP), h.deps()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if pin := h.pinned(t, "10.0.0.7"); pin == nil || pin.Fingerprint != firstFP {
		t.Fatalf("pin = %v, want the negotiated key %s", pin, firstFP)
	}
}

// removeFailingStore is a real store whose rotation step fails, so the
// half-way state — stale pin still present, replacement not yet added — is
// reachable in a test.
type removeFailingStore struct {
	knownhosts.Store
	err error
}

func (s *removeFailingStore) Remove(context.Context, sshscope.Scope, string, string) error {
	return s.err
}

// TestRun_RotationRemoveFailureIsTyped: when the stale pin cannot be removed,
// the replacement must NOT be added on top of it. Add refuses to overwrite, so
// a silent fallthrough would leave the operator believing a rotation happened.
func TestRun_RotationRemoveFailureIsTyped(t *testing.T) {
	old, oldFP := newHostKey(t)
	h := newHarness(t, old)
	if err := run(context.Background(), h.args("10.0.0.7", oldFP), h.deps()); err != nil {
		t.Fatalf("seed run: %v", err)
	}

	replacement, replacementFP := newHostKey(t)
	h.presents = replacement
	sentinel := errors.New("store is read-only")
	d := h.deps()
	d.openStore = func(dir string) (knownhosts.Store, error) {
		inner, err := openFileStore(dir)
		if err != nil {
			return nil, err
		}
		return &removeFailingStore{Store: inner, err: sentinel}, nil
	}

	err := run(context.Background(), h.args("10.0.0.7", replacementFP), d)

	var se *StoreError
	if !errors.As(err, &se) {
		t.Fatalf("run: got %v (%T), want *StoreError", err, err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("StoreError does not unwrap to the store failure: %v", err)
	}
	if !strings.Contains(se.Op, "rotate") {
		t.Errorf("StoreError.Op = %q, want it to name the rotation step", se.Op)
	}
	if pin := h.pinned(t, "10.0.0.7"); pin == nil || pin.Fingerprint != oldFP {
		t.Fatalf("pin = %v, want the original %s left in place by the failed rotation", pin, oldFP)
	}
}

// TestProductionDepsAreWired guards the one thing main does that a test cannot
// reach through run: handing it real dependencies rather than nil ones, which
// would panic on first use.
func TestProductionDepsAreWired(t *testing.T) {
	d := productionDeps()
	if d.capture == nil || d.openStore == nil || d.stdout == nil {
		t.Fatalf("productionDeps left a dependency nil: capture=%v openStore=%v stdout=%v",
			d.capture == nil, d.openStore == nil, d.stdout == nil)
	}
}

// TestUsageErrorUnwrapsFlagFailure: a flag the parser rejected has to stay
// inspectable, so a caller can report what the flag package objected to.
func TestUsageErrorUnwrapsFlagFailure(t *testing.T) {
	_, fp := newHostKey(t)
	_, err := parseArgs([]string{"--host", "h", "--dir", "/d", "--expect-fingerprint", fp, "--port", "ssh"})

	var ue *UsageError
	if !errors.As(err, &ue) {
		t.Fatalf("parseArgs: got %v (%T), want *UsageError", err, err)
	}
	if ue.Unwrap() == nil {
		t.Fatal("UsageError dropped the flag package's own error")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Errorf("error %q does not name the offending flag", err.Error())
	}

	// A structurally-incomplete command line has no underlying flag error.
	_, err = parseArgs([]string{"--host", "h", "--dir", "/d"})
	if !errors.As(err, &ue) {
		t.Fatalf("parseArgs: got %v (%T), want *UsageError", err, err)
	}
	if ue.Unwrap() != nil {
		t.Errorf("UsageError.Unwrap = %v, want nil for a missing mandatory flag", ue.Unwrap())
	}
}

// TestNoHostKeyErrorMessage covers both shapes: a handshake that failed for a
// reportable reason, and one that ended without the callback firing at all.
func TestNoHostKeyErrorMessage(t *testing.T) {
	withCause := &NoHostKeyError{Err: errors.New("connection refused")}
	if !strings.Contains(withCause.Error(), "connection refused") {
		t.Errorf("Error() = %q, want it to carry the dial failure", withCause.Error())
	}
	bare := &NoHostKeyError{}
	if bare.Error() != "no host key captured" {
		t.Errorf("Error() = %q, want the bare message", bare.Error())
	}
	if bare.Unwrap() != nil {
		t.Errorf("Unwrap = %v, want nil", bare.Unwrap())
	}
}

// listFailingStore is a real store whose existing-pin read fails, standing in
// for an unreadable backend.
type listFailingStore struct {
	knownhosts.Store
	err error
}

func (s *listFailingStore) List(context.Context, sshscope.Scope, string) ([]*knownhosts.Pin, error) {
	return nil, s.err
}

// corruptStoredPin overwrites every envelope under dir with bytes that will
// not decode, and returns what it wrote so a test can prove nothing touched
// them afterwards. The files are found by walking the store, so the test does
// not encode the backend's on-disk layout.
func corruptStoredPin(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	const garbage = `{"host":"10.0.0.7","fingerprint":`
	written := make(map[string][]byte)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if werr := os.WriteFile(path, []byte(garbage), 0o600); werr != nil {
			return werr
		}
		written[path] = []byte(garbage)
		return nil
	})
	if err != nil {
		t.Fatalf("corrupt stored pin: %v", err)
	}
	if len(written) == 0 {
		t.Fatal("no stored envelope found to corrupt — the seed run wrote nothing")
	}
	return written
}

// TestRun_CorruptExistingPinAbortsBeforeWriting is the fail-closed property on
// the READ side. An envelope that will not decode means the command cannot
// prove what is currently pinned; treating that as "nothing is pinned" would
// let it write over a record nobody could read. It must abort instead, before
// any Add or Remove.
func TestRun_CorruptExistingPinAbortsBeforeWriting(t *testing.T) {
	pub, fp := newHostKey(t)
	h := newHarness(t, pub)
	if err := run(context.Background(), h.args("10.0.0.7", fp), h.deps()); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	adds, removes := h.mutations()
	corrupted := corruptStoredPin(t, h.dir)

	// Same host, same verified key: the only thing that changed is that the
	// stored record is now unreadable.
	err := run(context.Background(), h.args("10.0.0.7", fp), h.deps())

	var se *StoreError
	if !errors.As(err, &se) {
		t.Fatalf("run: got %v (%T), want *StoreError — a corrupt envelope must not read as 'absent'", err, err)
	}
	if !strings.Contains(se.Op, "read") {
		t.Errorf("StoreError.Op = %q, want it to name the read step", se.Op)
	}
	if newAdds, newRemoves := h.mutations(); newAdds != adds || newRemoves != removes {
		t.Errorf("store mutated over an unreadable record: adds %d->%d, removes %d->%d", adds, newAdds, removes, newRemoves)
	}
	for path, want := range corrupted {
		got, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Errorf("stored envelope %s disappeared: %v", path, rerr)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("stored envelope %s was rewritten; it must be left exactly as found", path)
		}
	}
}

// TestRun_ExistingPinReadFailureAbortsBeforeWriting covers the other read
// failure: the backend itself errors. Same rule — no write may follow.
func TestRun_ExistingPinReadFailureAbortsBeforeWriting(t *testing.T) {
	pub, fp := newHostKey(t)
	h := newHarness(t, pub)
	sentinel := errors.New("backend unavailable")
	d := h.deps()
	d.openStore = func(dir string) (knownhosts.Store, error) {
		inner, err := openFileStore(dir)
		if err != nil {
			return nil, err
		}
		return &countingStore{Store: &listFailingStore{Store: inner, err: sentinel}}, nil
	}

	err := run(context.Background(), h.args("10.0.0.7", fp), d)

	var se *StoreError
	if !errors.As(err, &se) {
		t.Fatalf("run: got %v (%T), want *StoreError", err, err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("StoreError does not unwrap to the backend failure: %v", err)
	}
	if pin := h.pinned(t, "10.0.0.7"); pin != nil {
		t.Errorf("a pin was written despite an unreadable store: %v", pin)
	}
	if exitCode(err) != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode(err))
	}
}

// TestRun_AbsentPinIsNotAnError is the other half of the same distinction: an
// empty store is a clean first run, not a read failure, and must still pin.
// Without this, a fix that aborted on every read outcome would look correct.
func TestRun_AbsentPinIsNotAnError(t *testing.T) {
	pub, fp := newHostKey(t)
	h := newHarness(t, pub)

	store, err := openFileStore(h.dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	existing, err := existingPin(context.Background(), store, "10.0.0.7", "10.0.0.7")
	if err != nil {
		t.Fatalf("existingPin on an empty store: got error %v, want (nil, nil)", err)
	}
	if existing != nil {
		t.Fatalf("existingPin on an empty store returned %v, want nil", existing)
	}

	if err := run(context.Background(), h.args("10.0.0.7", fp), h.deps()); err != nil {
		t.Fatalf("first run against an empty store: %v", err)
	}
	if pin := h.pinned(t, "10.0.0.7"); pin == nil || pin.Fingerprint != fp {
		t.Fatalf("pin = %v, want %s persisted on a clean first run", pin, fp)
	}
}

// TestExistingPin_IgnoresOtherHostsUnderSameOwner: the lookup scans the owner
// prefix, so it has to return the requested host's pin and not a neighbour's.
func TestExistingPin_IgnoresOtherHostsUnderSameOwner(t *testing.T) {
	pubA, fpA := newHostKey(t)
	pubB, fpB := newHostKey(t)
	h := newHarness(t, pubA)
	argsFor := func(host, expect string) []string {
		return []string{"--host", host, "--owner", "fleet", "--dir", h.dir, "--expect-fingerprint", expect}
	}
	if err := run(context.Background(), argsFor("10.0.0.7", fpA), h.deps()); err != nil {
		t.Fatalf("seed host A: %v", err)
	}
	h.presents = pubB
	if err := run(context.Background(), argsFor("10.0.0.8", fpB), h.deps()); err != nil {
		t.Fatalf("seed host B: %v", err)
	}

	store, err := openFileStore(h.dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	for host, want := range map[string]string{"10.0.0.7": fpA, "10.0.0.8": fpB} {
		got, gerr := existingPin(context.Background(), store, "fleet", host)
		if gerr != nil {
			t.Fatalf("existingPin(%s): %v", host, gerr)
		}
		if got == nil || got.Fingerprint != want {
			t.Errorf("existingPin(%s) = %v, want fingerprint %s", host, got, want)
		}
	}
	missing, gerr := existingPin(context.Background(), store, "fleet", "10.0.0.9")
	if gerr != nil || missing != nil {
		t.Errorf("existingPin(unpinned host) = (%v, %v), want (nil, nil)", missing, gerr)
	}
}

// getFailingStore is a real store whose Get fails while List still works,
// which is how "a record exists but cannot be read" looks from here.
type getFailingStore struct {
	knownhosts.Store
	err error
}

func (s *getFailingStore) Get(context.Context, sshscope.Scope, string, string) (*knownhosts.Pin, error) {
	return nil, s.err
}

// TestExistingPin_NeighbourCorruptionDoesNotBlockAReadableHost pins the blast
// radius of the read. A host whose own record reads cleanly must be
// pinnable/rotatable regardless of what other hosts under the same owner look
// like — the readable host's Get is the only call the outcome depends on.
func TestExistingPin_NeighbourCorruptionDoesNotBlockAReadableHost(t *testing.T) {
	pubA, fpA := newHostKey(t)
	pubB, fpB := newHostKey(t)
	h := newHarness(t, pubA)
	argsFor := func(host, expect string) []string {
		return []string{"--host", host, "--owner", "fleet", "--dir", h.dir, "--expect-fingerprint", expect}
	}
	if err := run(context.Background(), argsFor("10.0.0.7", fpA), h.deps()); err != nil {
		t.Fatalf("seed host A: %v", err)
	}
	h.presents = pubB
	if err := run(context.Background(), argsFor("10.0.0.8", fpB), h.deps()); err != nil {
		t.Fatalf("seed host B: %v", err)
	}

	// Corrupt ONLY host B's envelope, identified by reading each file back.
	var corrupted int
	err := filepath.Walk(h.dir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() {
			return werr
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if !strings.Contains(string(data), "10.0.0.8") {
			return nil
		}
		corrupted++
		return os.WriteFile(path, []byte(`{"host":"10.0.0.8","fingerprint":`), 0o600)
	})
	if err != nil {
		t.Fatalf("corrupt host B: %v", err)
	}
	if corrupted != 1 {
		t.Fatalf("corrupted %d envelopes, want exactly host B's", corrupted)
	}

	// Host A still reads cleanly, so it must be readable and rotatable.
	store, err := openFileStore(h.dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	got, gerr := existingPin(context.Background(), store, "fleet", "10.0.0.7")
	if gerr != nil {
		t.Fatalf("existingPin(10.0.0.7) = %v; a neighbour's corrupt record must not block a readable host", gerr)
	}
	if got == nil || got.Fingerprint != fpA {
		t.Fatalf("existingPin(10.0.0.7) = %v, want fingerprint %s", got, fpA)
	}

	replacement, replacementFP := newHostKey(t)
	h.presents = replacement
	if rerr := run(context.Background(), argsFor("10.0.0.7", replacementFP), h.deps()); rerr != nil {
		t.Fatalf("rotating a readable host next to a corrupt neighbour: %v", rerr)
	}
	if pin := h.pinned2(t, "fleet", "10.0.0.7"); pin == nil || pin.Fingerprint != replacementFP {
		t.Fatalf("pin = %v, want the rotated fingerprint %s", pin, replacementFP)
	}
}

// TestExistingPin_UnreadableRecordReportsGetsOwnError: when a record for the
// host exists but Get cannot read it, the caller gets Get's own failure — the
// precise one — rather than a generic listing error.
func TestExistingPin_UnreadableRecordReportsGetsOwnError(t *testing.T) {
	pub, fp := newHostKey(t)
	h := newHarness(t, pub)
	if err := run(context.Background(), h.args("10.0.0.7", fp), h.deps()); err != nil {
		t.Fatalf("seed run: %v", err)
	}

	inner, err := openFileStore(h.dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	sentinel := errors.New("envelope unreadable")
	got, gerr := existingPin(context.Background(), &getFailingStore{Store: inner, err: sentinel}, "10.0.0.7", "10.0.0.7")
	if got != nil {
		t.Errorf("existingPin returned a pin %v despite an unreadable record", got)
	}
	if !errors.Is(gerr, sentinel) {
		t.Fatalf("existingPin = %v, want Get's own error %v", gerr, sentinel)
	}
}

// TestExistingPin_AbsentHostWithFailingGetIsNotAnError: Get fails because the
// host genuinely has no record, List confirms the absence, and the caller is
// told "absent" rather than "broken" — otherwise no first pin could be made.
func TestExistingPin_AbsentHostWithFailingGetIsNotAnError(t *testing.T) {
	pub, fp := newHostKey(t)
	h := newHarness(t, pub)
	if err := run(context.Background(), h.args("10.0.0.7", fp), h.deps()); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	inner, err := openFileStore(h.dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	// Get always fails; the requested host is one the store does not hold.
	got, gerr := existingPin(context.Background(),
		&getFailingStore{Store: inner, err: errors.New("not found")}, "10.0.0.7", "10.0.0.99")
	if gerr != nil || got != nil {
		t.Fatalf("existingPin(absent host) = (%v, %v), want (nil, nil)", got, gerr)
	}
}

// TestRun_HelpIsASuccessfulPath: -h/--help asks for the usage text; it is not
// a malformed command line. flag.ExitOnError exits 0 for it, scripts probe
// binaries with --help to test for availability, and the text must arrive
// without an error banner in front of it. It must also reach neither the
// target nor the store.
func TestRun_HelpIsASuccessfulPath(t *testing.T) {
	for _, arg := range []string{"--help", "-h"} {
		t.Run(arg, func(t *testing.T) {
			pub, _ := newHostKey(t)
			h := newHarness(t, pub)

			err := run(context.Background(), []string{arg}, h.deps())

			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("run(%s): got %v, want it to carry flag.ErrHelp", arg, err)
			}
			if got := exitCode(err); got != 0 {
				t.Errorf("exitCode = %d, want 0 — --help is a successful request", got)
			}
			var out strings.Builder
			report(err, &out)
			if !strings.Contains(out.String(), "usage: deployer-pin") {
				t.Errorf("report = %q, want the usage text", out.String())
			}
			if strings.Contains(out.String(), "deployer-pin: ") {
				t.Errorf("report printed an error banner for --help:\n%s", out.String())
			}
			if h.dials != 0 || h.opens != 0 {
				t.Errorf("--help dialed %d times and opened the store %d times, want 0/0", h.dials, h.opens)
			}
		})
	}
}

// addFailingStore is a real store whose Add fails, optionally only after the
// first N successful calls, so a rotation's replacement write can be made to
// fail while the seed pin still lands.
type addFailingStore struct {
	knownhosts.Store
	failAfter int
	calls     int
	err       error
	rollback  error // when set, the restoring Add fails too
}

func (s *addFailingStore) Add(ctx context.Context, pin *knownhosts.Pin) error {
	s.calls++
	if s.calls <= s.failAfter {
		return s.Store.Add(ctx, pin)
	}
	if s.calls == s.failAfter+1 {
		return s.err
	}
	if s.rollback != nil {
		return s.rollback
	}
	return s.Store.Add(ctx, pin)
}

// TestRun_FailedRotationRestoresThePreviousPin is the recoverability property.
// Rotation is remove-then-add because Add never overwrites, so there is a
// window with no pin. If the replacement does not land, the old pin must come
// back — the deployer is fail-closed, so leaving the host unpinned turns a
// recoverable write failure into an outage on that host.
func TestRun_FailedRotationRestoresThePreviousPin(t *testing.T) {
	old, oldFP := newHostKey(t)
	h := newHarness(t, old)
	sentinel := errors.New("disk full")
	var wrapped *addFailingStore
	d := h.deps()
	d.openStore = func(dir string) (knownhosts.Store, error) {
		if wrapped == nil {
			inner, err := openFileStore(dir)
			if err != nil {
				return nil, err
			}
			// The seed Add succeeds; the rotation's replacement Add fails.
			wrapped = &addFailingStore{Store: inner, failAfter: 1, err: sentinel}
		}
		return wrapped, nil
	}
	if err := run(context.Background(), h.args("10.0.0.7", oldFP), d); err != nil {
		t.Fatalf("seed run: %v", err)
	}

	replacement, replacementFP := newHostKey(t)
	h.presents = replacement
	err := run(context.Background(), h.args("10.0.0.7", replacementFP), d)

	var se *StoreError
	if !errors.As(err, &se) {
		t.Fatalf("run: got %v (%T), want *StoreError", err, err)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error does not unwrap to the write failure: %v", err)
	}
	if !strings.Contains(se.Op, "restored") {
		t.Errorf("StoreError.Op = %q, want it to say the previous pin was restored", se.Op)
	}
	// The point of the test: the host is still pinned, to the ORIGINAL key.
	pin := h.pinned(t, "10.0.0.7")
	if pin == nil {
		t.Fatal("the host was left UNPINNED by a failed rotation")
	}
	if pin.Fingerprint != oldFP {
		t.Fatalf("pin = %s, want the original %s restored", pin.Fingerprint, oldFP)
	}
}

// TestRun_FailedRotationAndFailedRollbackIsReportedDistinctly: when the old pin
// cannot be put back either, the host really is unpinned. That is a different
// situation from a retryable write failure and must not be reported as one —
// the operator has to act, not retry.
func TestRun_FailedRotationAndFailedRollbackIsReportedDistinctly(t *testing.T) {
	old, oldFP := newHostKey(t)
	h := newHarness(t, old)
	addErr := errors.New("disk full")
	rollbackErr := errors.New("store went read-only")
	var wrapped *addFailingStore
	d := h.deps()
	d.openStore = func(dir string) (knownhosts.Store, error) {
		if wrapped == nil {
			inner, err := openFileStore(dir)
			if err != nil {
				return nil, err
			}
			wrapped = &addFailingStore{Store: inner, failAfter: 1, err: addErr, rollback: rollbackErr}
		}
		return wrapped, nil
	}
	if err := run(context.Background(), h.args("10.0.0.7", oldFP), d); err != nil {
		t.Fatalf("seed run: %v", err)
	}

	replacement, replacementFP := newHostKey(t)
	h.presents = replacement
	err := run(context.Background(), h.args("10.0.0.7", replacementFP), d)

	var rre *RotationRollbackError
	if !errors.As(err, &rre) {
		t.Fatalf("run: got %v (%T), want *RotationRollbackError", err, err)
	}
	if rre.Host != "10.0.0.7" || rre.Fingerprint != oldFP {
		t.Errorf("error carries Host=%q Fingerprint=%q, want 10.0.0.7 / %s", rre.Host, rre.Fingerprint, oldFP)
	}
	if !errors.Is(err, addErr) {
		t.Errorf("error does not unwrap to the write failure: %v", err)
	}
	if rre.RollbackErr == nil || !errors.Is(rre.RollbackErr, rollbackErr) {
		t.Errorf("RollbackErr = %v, want the rollback failure", rre.RollbackErr)
	}
	msg := rre.Error()
	for _, want := range []string{"UNPINNED", "10.0.0.7", oldFP} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not mention %q — the operator must be told the host is unpinned", msg, want)
		}
	}
	if exitCode(err) != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode(err))
	}
}

// TestOpenFileStoreRejectsPreExistingPermissiveDir is the second finding:
// os.MkdirAll applies its mode only when it CREATES the directory, so a store
// root that already exists keeps whatever permissions it had. Anyone who can
// write there chooses which host key the fleet's install path trusts.
func TestOpenFileStoreRejectsPreExistingPermissiveDir(t *testing.T) {
	for name, mode := range map[string]os.FileMode{
		"world writable":      0o777,
		"group writable":      0o770,
		"other write only":    0o702,
		"group write only":    0o720,
		"sticky and writable": os.ModeSticky | 0o777,
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(privateTempDir(t), "known_hosts.d")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			// Set the mode explicitly: Mkdir's mode is filtered by umask.
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			_, err := openFileStore(dir)

			var ise *InsecureStoreDirError
			if !errors.As(err, &ise) {
				t.Fatalf("openFileStore(mode %o): got %v (%T), want *InsecureStoreDirError", mode, err, err)
			}
			if !strings.Contains(ise.Reason, "chmod go-w") {
				t.Errorf("Reason = %q, want it to name the fix", ise.Reason)
			}
			// The mode must not be silently repaired underneath the operator.
			info, serr := os.Stat(dir)
			if serr != nil {
				t.Fatalf("stat: %v", serr)
			}
			if info.Mode().Perm() != mode.Perm() {
				t.Errorf("directory mode changed to %o (want %o); the command must refuse, not silently chmod", info.Mode().Perm(), mode.Perm())
			}
		})
	}
}

// TestOpenFileStoreAcceptsPreExistingPrivateDir: a store root that is already
// 0700 is exactly what this command creates, so it must be accepted — a check
// that rejected everything would pass the rejection tests and be useless.
func TestOpenFileStoreAcceptsPreExistingPrivateDir(t *testing.T) {
	dir := filepath.Join(privateTempDir(t), "known_hosts.d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	store, err := openFileStore(dir)
	if err != nil {
		t.Fatalf("openFileStore on a 0700 dir: %v", err)
	}
	if store == nil {
		t.Fatal("openFileStore returned a nil store and no error")
	}
}

// TestOpenFileStoreRejectsSymlinkedRoot: MkdirAll and every later write follow
// a symlink, so whoever controls the link controls where the pins land — no
// matter how the target itself is permissioned.
func TestOpenFileStoreRejectsSymlinkedRoot(t *testing.T) {
	base := privateTempDir(t)
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(base, "known_hosts.d")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s: %v", link, err)
	}

	_, err := openFileStore(link)

	var ise *InsecureStoreDirError
	if !errors.As(err, &ise) {
		t.Fatalf("openFileStore(symlink): got %v (%T), want *InsecureStoreDirError", err, err)
	}
	if !strings.Contains(ise.Reason, "symlink") {
		t.Errorf("Reason = %q, want it to name the symlink", ise.Reason)
	}
}

// TestOpenFileStoreRejectsFileAsStoreRoot: --dir pointing at a regular file
// must be refused rather than producing a confusing backend error.
func TestOpenFileStoreRejectsFileAsStoreRoot(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "not-a-dir")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := openFileStore(path); err == nil {
		t.Fatal("openFileStore accepted a regular file as the store root")
	}
}

// TestRun_RefusesToPinIntoAPermissiveStore ties the check to the command: a
// tamperable store root must stop the run before a pin is written into it.
func TestRun_RefusesToPinIntoAPermissiveStore(t *testing.T) {
	pub, fp := newHostKey(t)
	h := newHarness(t, pub)
	if err := os.MkdirAll(h.dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(h.dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	err := run(context.Background(), h.args("10.0.0.7", fp), deps{
		capture:   func(string, int) (ssh.PublicKey, error) { return pub, nil },
		openStore: openFileStore,
		stdout:    &h.stdout,
	})

	var ise *InsecureStoreDirError
	if !errors.As(err, &ise) {
		t.Fatalf("run: got %v (%T), want *InsecureStoreDirError", err, err)
	}
	var se *StoreError
	if !errors.As(err, &se) {
		t.Errorf("the failure should still be reported as a StoreError: %v", err)
	}
	if exitCode(err) != 1 {
		t.Errorf("exitCode = %d, want 1", exitCode(err))
	}
	entries, rerr := os.ReadDir(h.dir)
	if rerr != nil {
		t.Fatalf("readdir: %v", rerr)
	}
	if len(entries) != 0 {
		t.Errorf("the store directory holds %d entries; nothing may be written into a tamperable store", len(entries))
	}
}

// TestCheckStoreDirStatFailure covers the branch where the store root cannot
// be inspected at all. openFileStore normally creates the directory first, so
// this is reachable only directly — but a check that cannot see the directory
// must report that rather than pass it.
func TestCheckStoreDirStatFailure(t *testing.T) {
	missing := filepath.Join(privateTempDir(t), "no", "such", "dir")
	err := checkStoreDir(missing)
	if err == nil {
		t.Fatal("checkStoreDir accepted a directory it could not stat")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want it to wrap os.ErrNotExist", err)
	}
}

// TestCheckStoreDirAcceptsOwnedPrivateDir is the positive control for the
// ownership rule: a 0700 directory owned by the invoking user passes, so the
// rejection tests above are not passing merely because everything is rejected.
func TestCheckStoreDirAcceptsOwnedPrivateDir(t *testing.T) {
	dir := filepath.Join(privateTempDir(t), "store")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := checkStoreDir(dir); err != nil {
		t.Fatalf("checkStoreDir on an owned 0700 dir: %v", err)
	}
}

// TestCheckStoreDirRejectsWritableAncestor: locking the leaf down is not
// enough. If a directory above it is writable by others, they can rename the
// checked 0700 directory aside and put their own in its place — before the
// first write or long after the last — and the deployer then verifies host
// keys against a store they control.
func TestCheckStoreDirRejectsWritableAncestor(t *testing.T) {
	for name, mode := range map[string]os.FileMode{
		"world writable parent": 0o777,
		"group writable parent": 0o775,
		// Other-writable but NOT group-writable: a mask that only looked at
		// the group bit would let this through.
		"other writable only": 0o707,
	} {
		t.Run(name, func(t *testing.T) {
			base := privateTempDir(t)
			shared := filepath.Join(base, "shared")
			store := filepath.Join(shared, "known_hosts.d")
			if err := os.MkdirAll(store, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.Chmod(store, 0o700); err != nil {
				t.Fatalf("chmod store: %v", err)
			}
			if err := os.Chmod(shared, mode); err != nil {
				t.Fatalf("chmod parent: %v", err)
			}

			err := checkStoreDir(store)

			var ise *InsecureStoreDirError
			if !errors.As(err, &ise) {
				t.Fatalf("checkStoreDir with a %o parent: got %v (%T), want *InsecureStoreDirError", mode, err, err)
			}
			if !strings.Contains(ise.Reason, shared) {
				t.Errorf("Reason = %q, want it to name the offending ancestor %s", ise.Reason, shared)
			}
		})
	}
}

// TestCheckStoreDirAllowsStickyAncestor is the distinction that makes the
// ancestor rule usable. On a sticky directory — /tmp, mode 1777 — a user may
// unlink or rename only entries they own, so the swap the rule guards against
// is not available. Rejecting writability alone would refuse every store under
// /tmp for no gain, and a check that fires spuriously is a check that gets
// turned off.
func TestCheckStoreDirAllowsStickyAncestor(t *testing.T) {
	base := privateTempDir(t)
	shared := filepath.Join(base, "shared")
	store := filepath.Join(shared, "known_hosts.d")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(store, 0o700); err != nil {
		t.Fatalf("chmod store: %v", err)
	}
	// 1777, exactly like /tmp.
	if err := os.Chmod(shared, os.ModeSticky|0o777); err != nil {
		t.Fatalf("chmod parent sticky: %v", err)
	}

	if err := checkStoreDir(store); err != nil {
		t.Fatalf("checkStoreDir under a sticky 1777 parent: %v; a sticky directory does not permit the swap", err)
	}
}

// TestRun_RefusesToPinUnderAWritableAncestor ties the ancestor rule to the
// command: nothing may be written into a store that can be redirected.
func TestRun_RefusesToPinUnderAWritableAncestor(t *testing.T) {
	pub, fp := newHostKey(t)
	base := privateTempDir(t)
	shared := filepath.Join(base, "shared")
	store := filepath.Join(shared, "known_hosts.d")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(store, 0o700); err != nil {
		t.Fatalf("chmod store: %v", err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatalf("chmod parent: %v", err)
	}

	var out strings.Builder
	err := run(context.Background(),
		[]string{"--host", "10.0.0.7", "--dir", store, "--expect-fingerprint", fp},
		deps{
			capture:   func(string, int) (ssh.PublicKey, error) { return pub, nil },
			openStore: openFileStore,
			stdout:    &out,
		})

	var ise *InsecureStoreDirError
	if !errors.As(err, &ise) {
		t.Fatalf("run: got %v (%T), want *InsecureStoreDirError", err, err)
	}
	entries, rerr := os.ReadDir(store)
	if rerr != nil {
		t.Fatalf("readdir: %v", rerr)
	}
	if len(entries) != 0 {
		t.Errorf("the store holds %d entries; nothing may be written into a redirectable store", len(entries))
	}
}

// TestCheckStoreDirRejectsWritableGrandparent: the walk has to continue to the
// filesystem root, not stop at the immediate parent. A swappable directory two
// levels up redirects the store just as effectively as one directly above it —
// renaming the intermediate directory carries the whole subtree with it.
func TestCheckStoreDirRejectsWritableGrandparent(t *testing.T) {
	base := privateTempDir(t)
	outer := filepath.Join(base, "outer")
	inner := filepath.Join(outer, "inner")
	store := filepath.Join(inner, "known_hosts.d")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Everything below is locked down; only the grandparent is loose.
	for _, p := range []string{store, inner} {
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
	if err := os.Chmod(outer, 0o777); err != nil {
		t.Fatalf("chmod grandparent: %v", err)
	}

	err := checkStoreDir(store)

	var ise *InsecureStoreDirError
	if !errors.As(err, &ise) {
		t.Fatalf("checkStoreDir with a writable grandparent: got %v (%T), want *InsecureStoreDirError", err, err)
	}
	if !strings.Contains(ise.Reason, outer) {
		t.Errorf("Reason = %q, want it to name the grandparent %s", ise.Reason, outer)
	}
}

// TestOpenFileStoreAcceptsNonWritableSharedModes is the counterweight to the
// rejection table: the integrity risk is WRITE access, not visibility. A
// fingerprint is public — it is read off the host's console — so group/other
// read and execute bits give an attacker nothing. The documented deployment
// layout is a root-owned 0755 /etc/platform/deployer, and refusing that would
// make the normal install impossible in order to hide published values.
func TestOpenFileStoreAcceptsNonWritableSharedModes(t *testing.T) {
	for name, mode := range map[string]os.FileMode{
		"the /etc layout (0755)":  0o755,
		"group readable (0750)":   0o750,
		"other execute (0701)":    0o701,
		"group traversal (0710)":  0o710,
		"owner only (0700)":       0o700,
		"read-only to all (0755)": 0o755,
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(privateTempDir(t), "known_hosts.d")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			store, err := openFileStore(dir)
			if err != nil {
				t.Fatalf("openFileStore(mode %o): %v; no group/other WRITE bit is set, so nobody else can tamper", mode, err)
			}
			if store == nil {
				t.Fatal("openFileStore returned a nil store and no error")
			}
		})
	}
}

// TestRun_PinsIntoAWorldReadableEtcStyleStore proves the acceptance end to end:
// the command must actually provision into the documented 0755 layout, not
// merely pass a unit check.
func TestRun_PinsIntoAWorldReadableEtcStyleStore(t *testing.T) {
	pub, fp := newHostKey(t)
	dir := filepath.Join(privateTempDir(t), "deployer")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	var out strings.Builder
	err := run(context.Background(),
		[]string{"--host", "10.0.0.7", "--dir", dir, "--expect-fingerprint", fp},
		deps{
			capture:   func(string, int) (ssh.PublicKey, error) { return pub, nil },
			openStore: openFileStore,
			stdout:    &out,
		})
	if err != nil {
		t.Fatalf("run against a 0755 store: %v", err)
	}

	store, oerr := openFileStore(dir)
	if oerr != nil {
		t.Fatalf("reopen: %v", oerr)
	}
	pin, gerr := store.Get(context.Background(), sshscope.Service, "10.0.0.7", "10.0.0.7")
	if gerr != nil || pin == nil || pin.Fingerprint != fp {
		t.Fatalf("pin = %v (err %v), want %s persisted", pin, gerr, fp)
	}
}

// TestAncestorOwnerAllowed covers the ownership rule directly, since creating
// a directory owned by a third user needs root. Root is allowed because every
// path traverses root-owned system directories; the invoking user is allowed
// because they already control their own tree; anyone else can rename the
// store aside.
func TestAncestorOwnerAllowed(t *testing.T) {
	for name, tc := range map[string]struct {
		owner uint32
		uid   int
		want  bool
	}{
		"root-owned, running as root":      {0, 0, true},
		"root-owned, running as a user":    {0, 1000, true},
		"self-owned, running as that user": {1000, 1000, true},
		"self-owned, running as root":      {1000, 0, false},
		"another user, running as root":    {1001, 0, false},
		"another user, running as a user":  {1001, 1000, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ancestorOwnerAllowed(tc.owner, tc.uid); got != tc.want {
				t.Errorf("ancestorOwnerAllowed(%d, %d) = %v, want %v", tc.owner, tc.uid, got, tc.want)
			}
		})
	}
}

// TestCheckStoreDirAllowsSymlinkedAncestor: Lstat on an unresolved component
// reports the symlink's own mode, which POSIX ignores and which is always
// 0777. Walking the literal path would therefore reject any store beneath a
// standard symlinked directory — /var/run, a symlink to /run on most Linux
// systems, is the everyday case. The walk resolves first, so a safe chain
// behind a symlink is accepted.
func TestCheckStoreDirAllowsSymlinkedAncestor(t *testing.T) {
	base := privateTempDir(t)
	real := filepath.Join(base, "real")
	store := filepath.Join(real, "known_hosts.d")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, p := range []string{store, real} {
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink %s: %v", link, err)
	}

	// The store reached THROUGH the symlinked ancestor. The leaf itself is a
	// real directory; only the component above it is a link.
	viaLink := filepath.Join(link, "known_hosts.d")
	if err := checkStoreDir(viaLink); err != nil {
		t.Fatalf("checkStoreDir via a symlinked ancestor: %v; the resolved chain is 0700 and owned by the caller", err)
	}

	// And the command provisions through it.
	pub, fp := newHostKey(t)
	var out strings.Builder
	if rerr := run(context.Background(),
		[]string{"--host", "10.0.0.7", "--dir", viaLink, "--expect-fingerprint", fp},
		deps{
			capture:   func(string, int) (ssh.PublicKey, error) { return pub, nil },
			openStore: openFileStore,
			stdout:    &out,
		}); rerr != nil {
		t.Fatalf("run via a symlinked ancestor: %v", rerr)
	}
}

// TestCheckStoreDirRejectsWritableAncestorBehindSymlink: resolving must not
// become a way to launder an unsafe chain. A world-writable directory is still
// refused when it is reached through a symlink.
func TestCheckStoreDirRejectsWritableAncestorBehindSymlink(t *testing.T) {
	base := privateTempDir(t)
	shared := filepath.Join(base, "shared")
	store := filepath.Join(shared, "known_hosts.d")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(store, 0o700); err != nil {
		t.Fatalf("chmod store: %v", err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatalf("chmod shared: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(shared, link); err != nil {
		t.Fatalf("symlink %s: %v", link, err)
	}

	err := checkStoreDir(filepath.Join(link, "known_hosts.d"))

	var ise *InsecureStoreDirError
	if !errors.As(err, &ise) {
		t.Fatalf("checkStoreDir: got %v (%T), want *InsecureStoreDirError — resolving must not hide a writable ancestor", err, err)
	}
	if !strings.Contains(ise.Reason, shared) {
		t.Errorf("Reason = %q, want it to name the resolved directory %s", ise.Reason, shared)
	}
}

// TestCheckStoreDirAcceptsRootOwnedSystemAncestors is the realism check: the
// documented layout lives under root-owned system directories, and the walk
// must accept them. /tmp is root-owned and sticky, and every path above it is
// root-owned, which is exactly the shape of /etc/platform/deployer.
func TestCheckStoreDirAcceptsRootOwnedSystemAncestors(t *testing.T) {
	dir := filepath.Join(privateTempDir(t), "known_hosts.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := checkStoreDir(dir); err != nil {
		t.Fatalf("checkStoreDir under root-owned system ancestors: %v", err)
	}
}

// TestCheckStoreAncestorsRejectsAncestorOwnedByAnotherUser is the /home/alice
// case: root provisions into /home/alice/known_hosts.d, the leaf is 0700, and
// alice — who owns /home/alice at 0755 — can still rename it aside and put her
// own store there afterwards. Mode alone never catches this, because 0755 is
// not "writable by others" in the mode sense.
//
// Setting it up for real needs root, so the walk takes the invoking uid as a
// parameter: running it against a uid that owns nothing on the path reproduces
// exactly the same condition.
// ownedBy wraps a real fs.FileInfo and reports a different owning uid, so the
// ancestor-ownership rule can be exercised without a directory owned by a
// third user — which cannot be created without root, and which cannot be
// created AT ALL under root in a way this rule rejects, since root-owned
// ancestors are allowed by design.
type ownedBy struct {
	fs.FileInfo
	uid uint32
}

func (o ownedBy) Sys() any {
	st, ok := o.FileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return o.FileInfo.Sys()
	}
	dup := *st
	dup.Uid = o.uid
	return &dup
}

func TestCheckStoreAncestorsRejectsAncestorOwnedByAnotherUser(t *testing.T) {
	base := privateTempDir(t) // owned by the test user, mode 0700
	store := filepath.Join(base, "known_hosts.d")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(store)
	if err != nil {
		t.Fatalf("evalsymlinks: %v", err)
	}
	parent := filepath.Dir(resolved)

	// A uid owning neither the tree nor root. Chosen so it differs from the
	// invoking user whether the suite runs as root (CI) or as a human.
	const stranger = uint32(31337)
	if int(stranger) == os.Getuid() {
		t.Fatalf("test precondition: stranger uid %d must differ from the invoking uid", stranger)
	}

	// Present the immediate parent as owned by the stranger; every other
	// component stats normally.
	lstat := func(path string) (fs.FileInfo, error) {
		info, serr := os.Lstat(path)
		if serr != nil {
			return nil, serr
		}
		if path == parent {
			return ownedBy{FileInfo: info, uid: stranger}, nil
		}
		return info, nil
	}

	err = checkStoreAncestorsWith(store, os.Getuid(), lstat)
	var ise *InsecureStoreDirError
	if !errors.As(err, &ise) {
		t.Fatalf("checkStoreAncestorsWith with a stranger-owned parent: got %v (%T), want *InsecureStoreDirError — an ancestor owned by someone else can be renamed aside", err, err)
	}
	if !strings.Contains(ise.Reason, "owned by uid") {
		t.Errorf("Reason = %q, want it to name the ownership problem", ise.Reason)
	}
	if !strings.Contains(ise.Reason, strconv.FormatUint(uint64(stranger), 10)) {
		t.Errorf("Reason = %q, want it to name the offending uid %d", ise.Reason, stranger)
	}

	// The same path, stated truthfully, is fine for the user who owns it.
	if err := checkStoreAncestorsWith(store, os.Getuid(), os.Lstat); err != nil {
		t.Fatalf("checkStoreAncestorsWith on the real tree as its owner: %v", err)
	}
}
