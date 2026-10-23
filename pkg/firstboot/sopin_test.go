package firstboot

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tpmowner"
)

// writeConfig writes a platformd configuration file into dir and returns its
// path.
func writeConfig(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

// soPINSources returns a configuration naming soPIN and a handoff path that
// does not exist yet, both under a fresh directory.
func soPINSources(t *testing.T, soPIN string) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := writeConfig(t, dir, "config.yaml", "platform:\n  so-pin: \""+soPIN+"\"\n")
	return []string{cfg}, filepath.Join(dir, "handoff", "so-pin")
}

// The first file that parses and carries a platform section wins; missing,
// malformed and platform-less files are passed over, as loadTPMConfig does.
func TestLoadSOPINRef_FirstPlatformSectionWins(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "missing.yaml"),
		writeConfig(t, dir, "malformed.yaml", "platform: [unterminated\n"),
		writeConfig(t, dir, "tpm-only.yaml", "tpm:\n  device: /dev/tpmrm0\n"),
		writeConfig(t, dir, "first.yaml", "platform:\n  so-pin: \"111111\"\n"),
		writeConfig(t, dir, "second.yaml", "platform:\n  so-pin: \"222222\"\n"),
	}
	ref, err := loadSOPINRef(paths)
	require.NoError(t, err)
	require.Equal(t, "111111", ref)
}

func TestLoadSOPINRef_NoPlatformSection(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "missing.yaml"), writeConfig(t, dir, "tpm-only.yaml", "tpm: {}\n")}
	_, err := loadSOPINRef(paths)
	require.ErrorIs(t, err, ErrSOPINConfigNotFound)
}

// A literal SO PIN is used as configured and nothing is staged: platformd
// reads the same literal.
func TestResolveSOPIN_Literal(t *testing.T) {
	paths, handoff := soPINSources(t, "123456")
	pw, err := resolveSOPIN(paths, handoff)
	require.NoError(t, err)
	require.Equal(t, []byte("123456"), pw.Bytes())
	require.NoFileExists(t, handoff)
}

// A kms:// SO PIN is generated in the form the reference names and staged,
// root only, for platformd to store at the KMS path.
func TestResolveSOPIN_KMSGeneratesAndStages(t *testing.T) {
	paths, handoff := soPINSources(t, "kms://platform/so-pin?ensure=true&len=8&enc=numeric")
	pw, err := resolveSOPIN(paths, handoff)
	require.NoError(t, err)
	require.Len(t, pw.Bytes(), 8)

	staged, err := os.ReadFile(handoff)
	require.NoError(t, err)
	require.Equal(t, pw.Bytes(), staged, "the staged PIN is the one ownership is taken with")
	info, err := os.Stat(handoff)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	dirInfo, err := os.Stat(filepath.Dir(handoff))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())
}

// A retried provisioning in the same boot reuses the PIN already staged, so it
// proves and keeps the owner auth an earlier attempt set.
func TestResolveSOPIN_KMSReusesStagedPIN(t *testing.T) {
	paths, handoff := soPINSources(t, "kms://platform/so-pin?ensure=true&len=8&enc=numeric")
	first, err := resolveSOPIN(paths, handoff)
	require.NoError(t, err)

	second, err := resolveSOPIN(paths, handoff)
	require.NoError(t, err)
	require.Equal(t, first.Bytes(), second.Bytes())
}

func TestResolveSOPIN_KMSStagedEmpty(t *testing.T) {
	paths, handoff := soPINSources(t, "kms://platform/so-pin?ensure=true&len=8&enc=numeric")
	require.NoError(t, writeHandoffFile(handoff, nil))

	_, err := resolveSOPIN(paths, handoff)
	require.ErrorIs(t, err, ErrSOPINHandoffEmpty)
}

// A handoff path that cannot be read for a reason other than absence fails
// the resolution instead of generating a second PIN.
func TestResolveSOPIN_KMSStagedUnreadable(t *testing.T) {
	paths, handoff := soPINSources(t, "kms://platform/so-pin?ensure=true&len=8&enc=numeric")
	require.NoError(t, os.MkdirAll(handoff, 0700))

	_, err := resolveSOPIN(paths, handoff)
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
}

// A PIN that cannot be staged is not used: platformd would never learn it.
func TestResolveSOPIN_KMSStageFailure(t *testing.T) {
	paths, _ := soPINSources(t, "kms://platform/so-pin?ensure=true&len=8&enc=numeric")
	// A dangling symlink reads as absent, and O_EXCL refuses to create
	// through it.
	dir := t.TempDir()
	handoff := filepath.Join(dir, "so-pin")
	require.NoError(t, os.Symlink(filepath.Join(dir, "nowhere"), handoff))

	pw, err := resolveSOPIN(paths, handoff)
	require.Nil(t, pw)
	require.ErrorIs(t, err, os.ErrExist)
	require.NoFileExists(t, filepath.Join(dir, "nowhere"), "nothing is written through the link")
}

// An SO PIN platformd would not reproduce is refused before the TPM is
// touched.
func TestResolveSOPIN_Refused(t *testing.T) {
	paths, handoff := soPINSources(t, "kms://platform/so-pin?len=8&enc=numeric")
	_, err := resolveSOPIN(paths, handoff)
	var refErr *tpmowner.SOPINRefError
	require.ErrorAs(t, err, &refErr)
	require.NoFileExists(t, handoff)
}

func TestResolveSOPIN_NotConfigured(t *testing.T) {
	paths, handoff := soPINSources(t, "")
	_, err := resolveSOPIN(paths, handoff)
	require.ErrorIs(t, err, tpmowner.ErrSOPINNotConfigured)
}

func TestResolveSOPIN_NoConfig(t *testing.T) {
	_, err := resolveSOPIN([]string{filepath.Join(t.TempDir(), "missing.yaml")}, filepath.Join(t.TempDir(), "so-pin"))
	require.ErrorIs(t, err, ErrSOPINConfigNotFound)
}

// O_EXCL: a staged secret is never overwritten.
func TestWriteHandoffFile_RefusesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "handoff", "secret")
	require.NoError(t, writeHandoffFile(path, []byte("first")))

	err := writeHandoffFile(path, []byte("second"))
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	require.ErrorIs(t, err, os.ErrExist)
	data, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, []byte("first"), data)
}

func TestWriteHandoffFile_DirectoryFailure(t *testing.T) {
	blocker := writeConfig(t, t.TempDir(), "not-a-dir", "")
	err := writeHandoffFile(filepath.Join(blocker, "sub", "secret"), []byte("x"))
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
}
