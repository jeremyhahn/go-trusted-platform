package arch

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// abuild copies an aport's sources with the mode the checkout gave them, and
// git records only the executable bit. A script an APKBUILD runs directly, or
// installs as an executable, must therefore be tracked executable, or the
// build fails on a fresh checkout with "Permission denied" (#762). Running it
// through sh is the other fix, and needs no bit.

// execSourcePattern matches the sources an APKBUILD needs executable: a line
// that starts with "$srcdir"/NAME (a direct run), and the NAME of an
// `install -Dm755 "$srcdir"/NAME`.
var execSourcePattern = regexp.MustCompile(`(?m)^\s*"\$srcdir"/([\w.-]+)|install -Dm755 "\$srcdir"/([\w.-]+)`)

// NotExecutableError reports a source an APKBUILD needs executable that the
// checkout does not carry as executable.
type NotExecutableError struct {
	Path string
	Mode os.FileMode
}

func (e *NotExecutableError) Error() string {
	return "ipsec packaging: " + e.Path + " is mode " + e.Mode.String() + ", the APKBUILD needs it executable"
}

// execSources returns the sources the APKBUILD text needs executable.
func execSources(apkbuild string) []string {
	var names []string
	for _, m := range execSourcePattern.FindAllStringSubmatch(apkbuild, -1) {
		names = append(names, m[1]+m[2])
	}
	return names
}

// requireExecutable fails unless the file at rel carries an executable bit.
func requireExecutable(root, rel string) error {
	info, err := os.Stat(filepath.Join(root, rel))
	if err != nil {
		return &PackagingFileError{Path: rel, Err: err}
	}
	if info.Mode().Perm()&0o111 == 0 {
		return &NotExecutableError{Path: rel, Mode: info.Mode().Perm()}
	}
	return nil
}

func TestExecSources(t *testing.T) {
	apkbuild := "\t\"$srcdir\"/direct \"$_ver\" || return 1\n" +
		"\tsh \"$srcdir\"/through-sh \"$_ver\"\n" +
		"\tinstall -Dm755 \"$srcdir\"/installed.initd \"$pkgdir\"/etc/init.d/x\n" +
		"\tinstall -Dm644 \"$srcdir\"/data.conf \"$pkgdir\"/etc/x.conf\n"
	assert.Equal(t, []string{"direct", "installed.initd"}, execSources(apkbuild))
	assert.Empty(t, execSources("build() {\n\treturn 0\n}\n"))
}

func TestRequireExecutable(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "run.sh"), []byte("#!/bin/sh\n"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "plain.sh"), []byte("#!/bin/sh\n"), 0o644))
	require.NoError(t, os.Chmod(filepath.Join(root, "run.sh"), 0o755))

	assert.NoError(t, requireExecutable(root, "run.sh"))

	var notExec *NotExecutableError
	require.ErrorAs(t, requireExecutable(root, "plain.sh"), &notExec)
	assert.Equal(t, "plain.sh", notExec.Path)

	var readErr *PackagingFileError
	require.ErrorAs(t, requireExecutable(root, "absent.sh"), &readErr)
}

// TestIPsecPackaging_ExecutedSourcesAreExecutable checks the checkout, so it
// fails on the mode git tracks, which is what a fresh clone gets.
func TestIPsecPackaging_ExecutedSourcesAreExecutable(t *testing.T) {
	root := repoRoot(t)
	for _, aport := range []string{strongSwanAport, p11HostAport} {
		apkbuild, err := readPackagingFile(root, aport+"/APKBUILD")
		require.NoError(t, err)
		sources := execSources(apkbuild)
		require.NotEmpty(t, sources, "%s installs no executable", aport)
		for _, name := range sources {
			t.Run(aport+"/"+name, func(t *testing.T) {
				// build-strongswan.sh stages the builder's shared scripts
				// into each aport; the aport's own copy wins.
				rel := aport + "/" + name
				if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
					rel = builderDir + "/" + name
				}
				assert.NoError(t, requireExecutable(root, rel))
			})
		}
	}
}
