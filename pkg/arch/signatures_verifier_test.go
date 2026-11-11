package arch

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSignaturesVerifier runs the Signatures job's verifier script, taken
// from ci.yml as it stands (never a copy), with bash against throwaway git
// repositories, and checks that it accepts a commit signed by a registered
// key whose principal is the committer and rejects everything else: an
// unsigned commit, an unknown key, a principal mismatch, a key that the head
// itself adds to the registry, and a GitHub-made commit the API does not
// vouch for (or cannot be asked about).
func TestSignaturesVerifier(t *testing.T) {
	script := signaturesVerifierScript(t)

	const (
		alice  = "alice@test.invalid"
		bob    = "bob@test.invalid"
		carol  = "carol@test.invalid"
		github = "noreply@github.com"
	)

	// base makes a repository whose first commit holds a registry naming
	// alice and bob, and returns it with the keys.
	type fixture struct {
		repo                *sigRepo
		base                string
		alice, bob, mallory sigKey
	}
	base := func(t *testing.T) fixture {
		t.Helper()
		r := newSigRepo(t)
		f := fixture{
			repo:    r,
			alice:   newSigKey(t, "alice"),
			bob:     newSigKey(t, "bob"),
			mallory: newSigKey(t, "mallory"),
		}
		f.base = r.commit(alice, f.alice, "add the registry", map[string]string{
			".github/allowed_signers": f.alice.registryLine(alice) + f.bob.registryLine(bob),
		})
		return f
	}
	change := map[string]string{"README": "a change\n"}

	webFlow := `{"commit":{"verification":{"verified":true,"reason":"valid"}},"committer":{"login":"web-flow"}}`
	notVerified := `{"commit":{"verification":{"verified":false,"reason":"unsigned"}},"committer":{"login":"web-flow"}}`

	tests := []struct {
		name string
		// head adds the head commit(s) on top of the base and returns the head.
		head  func(t *testing.T, f fixture) string
		curl  string
		rc    int
		wants []string
	}{
		{
			name: "registered key, principal is the committer",
			head: func(t *testing.T, f fixture) string {
				return f.repo.commit(alice, f.alice, "signed by alice", change)
			},
			rc:    0,
			wants: []string{"OK   ", "signed by " + alice},
		},
		{
			name: "unsigned commit",
			head: func(t *testing.T, f fixture) string {
				return f.repo.commit(alice, sigKey{}, "unsigned", change)
			},
			rc:    1,
			wants: []string{"FAIL", "unsigned"},
		},
		{
			name: "key not in the registry",
			head: func(t *testing.T, f fixture) string {
				return f.repo.commit(alice, f.mallory, "signed by mallory as alice", change)
			},
			rc:    1,
			wants: []string{"FAIL", "not in the registry"},
		},
		{
			name: "key registered to another principal",
			head: func(t *testing.T, f fixture) string {
				return f.repo.commit(alice, f.bob, "signed by bob as alice", change)
			},
			rc:    1,
			wants: []string{"FAIL", "principal mismatch"},
		},
		{
			name: "head adds its own key to the registry",
			head: func(t *testing.T, f fixture) string {
				carolKey := newSigKey(t, "carol")
				reg := f.alice.registryLine(alice) + f.bob.registryLine(bob) + carolKey.registryLine(carol)
				return f.repo.commit(carol, carolKey, "carol registers herself", map[string]string{
					".github/allowed_signers": reg,
				})
			},
			rc:    1,
			wants: []string{"FAIL", "not in the registry"},
		},
		{
			name: "GitHub commit verified as web-flow",
			head: func(t *testing.T, f fixture) string {
				return f.repo.commit(github, sigKey{}, "squash merge", change)
			},
			curl:  fakeCurlPrinting(webFlow),
			rc:    0,
			wants: []string{"OK   ", "GitHub web-flow, verified"},
		},
		{
			name: "GitHub commit, API unreadable",
			head: func(t *testing.T, f fixture) string {
				return f.repo.commit(github, sigKey{}, "squash merge", change)
			},
			curl:  "#!/bin/sh\nexit 22\n",
			rc:    1,
			wants: []string{"FAIL", "API could not be read"},
		},
		{
			name: "GitHub commit not verified",
			head: func(t *testing.T, f fixture) string {
				return f.repo.commit(github, sigKey{}, "squash merge", change)
			},
			curl:  fakeCurlPrinting(notVerified),
			rc:    1,
			wants: []string{"FAIL", "not verified"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := base(t)
			head := tc.head(t, f)
			rc, out := runSignaturesVerifier(t, script, f.repo, f.base, head, tc.curl)
			require.Equal(t, tc.rc, rc, "verifier output:\n%s", out)
			for _, want := range tc.wants {
				require.Contains(t, out, want, "verifier output:\n%s", out)
			}
		})
	}
}

// signaturesVerifierScript returns the run script of the one step of the
// signatures job that reads .github/allowed_signers.
func signaturesVerifierScript(t *testing.T) string {
	t.Helper()
	wf := loadCIWorkflow(t, repoRoot(t), ciWorkflowFile)
	var scripts []string
	for _, job := range wf.Jobs {
		if job.ID != "signatures" {
			continue
		}
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "allowed_signers") {
				scripts = append(scripts, step.Run)
			}
		}
	}
	require.Len(t, scripts, 1, "the signatures job must have exactly one step reading allowed_signers")
	return scripts[0]
}

// sigKey is an ed25519 key pair made by ssh-keygen; the zero value means
// "do not sign".
type sigKey struct {
	private string
	public  string // "<keytype> <base64>"
}

func newSigKey(t *testing.T, name string) sigKey {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-C", name, "-f", path).CombinedOutput()
	require.NoError(t, err, "ssh-keygen: %s", out)
	pub, err := os.ReadFile(path + ".pub")
	require.NoError(t, err)
	fields := strings.Fields(string(pub))
	require.GreaterOrEqual(t, len(fields), 2, "public key %q", pub)
	return sigKey{private: path, public: fields[0] + " " + fields[1]}
}

func (k sigKey) registryLine(principal string) string {
	return principal + ` namespaces="git" ` + k.public + "\n"
}

// sigRepo is a temporary git repository isolated from the user's and the
// system's git configuration.
type sigRepo struct {
	t   *testing.T
	dir string
	env []string
}

func newSigRepo(t *testing.T) *sigRepo {
	t.Helper()
	home := t.TempDir()
	r := &sigRepo{
		t:   t,
		dir: t.TempDir(),
		env: []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + home,
			"GIT_CONFIG_GLOBAL=" + os.DevNull,
			"GIT_CONFIG_NOSYSTEM=1",
		},
	}
	r.git(nil, "init", "-q", "-b", "main")
	return r
}

func (r *sigRepo) git(extraEnv []string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(append([]string{}, r.env...), extraEnv...)
	out, err := cmd.CombinedOutput()
	require.NoError(r.t, err, "git %s: %s", strings.Join(args, " "), out)
	return strings.TrimSpace(string(out))
}

// commit writes files, commits them as email (signed with key unless it is
// the zero key) and returns the new commit's SHA.
func (r *sigRepo) commit(email string, key sigKey, msg string, files map[string]string) string {
	r.t.Helper()
	for name, content := range files {
		path := filepath.Join(r.dir, name)
		require.NoError(r.t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(r.t, os.WriteFile(path, []byte(content), 0o644))
	}
	r.git(nil, "add", "-A")
	name := strings.SplitN(email, "@", 2)[0]
	env := []string{
		"GIT_AUTHOR_NAME=" + name, "GIT_AUTHOR_EMAIL=" + email,
		"GIT_COMMITTER_NAME=" + name, "GIT_COMMITTER_EMAIL=" + email,
	}
	args := []string{"-c", "gpg.format=ssh"}
	if key.private != "" {
		args = append(args, "-c", "user.signingkey="+key.private, "commit", "-q", "-S", "--allow-empty", "-m", msg)
	} else {
		args = append(args, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", msg)
	}
	r.git(env, args...)
	return r.git(nil, "rev-parse", "HEAD")
}

func fakeCurlPrinting(body string) string {
	return "#!/bin/sh\nprintf '%s\\n' '" + body + "'\n"
}

// runSignaturesVerifier runs the script with bash in the repository as a
// pull_request run from base to head. curl is a fake: the given script, or
// one that fails if none is given, so no case can reach the network.
func runSignaturesVerifier(t *testing.T, script string, r *sigRepo, base, head, curl string) (int, string) {
	t.Helper()
	bin := t.TempDir()
	if curl == "" {
		curl = "#!/bin/sh\necho 'fake curl: not expected in this case' >&2\nexit 7\n"
	}
	require.NoError(t, os.WriteFile(filepath.Join(bin, "curl"), []byte(curl), 0o755))

	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = r.dir
	cmd.Env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"RUNNER_TEMP=" + t.TempDir(),
		"EVENT=pull_request",
		"BASE_SHA=" + base,
		"HEAD_SHA=" + head,
		"BEFORE=",
		"REPO=owner/repo",
		"API=fake-api",
		"GH_TOKEN=fake-token",
	}
	out, err := cmd.CombinedOutput()
	rc := 0
	if err != nil {
		var exitErr *exec.ExitError
		require.True(t, errors.As(err, &exitErr), "bash: %v\n%s", err, out)
		rc = exitErr.ExitCode()
	}
	return rc, string(out)
}
