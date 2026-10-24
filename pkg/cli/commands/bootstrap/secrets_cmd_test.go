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

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	corebootstrap "github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

const (
	testSecretEnv   = "BS_TEST_DB_PASSWORD"
	testSecretValue = "s3cr3t-value"
	testUnsetEnv    = "BS_TEST_UNSET_SECRET"
	testMigrateKey  = "bootstrap-key"
)

// fakeKMSServer is an in-process KeyManagementService. It accepts only
// requests for testMigrateKey whose AAD is a config/ KMS path, refuses the
// plaintext failPlaintext, and counts every Encrypt call.
type fakeKMSServer struct {
	platformv1.UnimplementedKeyManagementServiceServer
	failPlaintext string
	calls         atomic.Int32
}

func (f *fakeKMSServer) Encrypt(_ context.Context, req *platformv1.EncryptRequest) (*platformv1.EncryptResponse, error) {
	f.calls.Add(1)
	if req.KeyId != testMigrateKey || !strings.HasPrefix(string(req.Context), "config/") {
		return nil, status.Error(codes.InvalidArgument, "unexpected key or context")
	}
	if f.failPlaintext != "" && string(req.Plaintext) == f.failPlaintext {
		return nil, status.Error(codes.Internal, "encrypt refused")
	}
	return &platformv1.EncryptResponse{KeyId: req.KeyId, Ciphertext: []byte("ciphertext")}, nil
}

// nilResultKMSClient answers Encrypt with neither a response nor an error,
// which a real gRPC transport cannot produce.
type nilResultKMSClient struct {
	platformv1.KeyManagementServiceClient
}

func (nilResultKMSClient) Encrypt(context.Context, *platformv1.EncryptRequest, ...grpc.CallOption) (*platformv1.EncryptResponse, error) {
	return nil, nil
}

type testContextError struct{}

func (testContextError) Error() string { return "no CLI context" }

// newSocketFlags serves gRPC on a unix socket (with kms registered when
// non-nil) and returns CLI flags whose local context dials it.
func newSocketFlags(t *testing.T, format cli.OutputFormat, kms platformv1.KeyManagementServiceServer) *cli.CommonFlags {
	t.Helper()

	// A short directory keeps the socket path under the 108-byte limit.
	dir, err := os.MkdirTemp("", "bs")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })

	socketPath := filepath.Join(dir, "p.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	server := grpc.NewServer()
	if kms != nil {
		platformv1.RegisterKeyManagementServiceServer(server, kms)
	}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		assert.NoError(t, <-served)
	})

	cliContext := &cli.Context{
		Name:  "bootstrap-secrets-test",
		Type:  cli.ContextTypeLocal,
		Local: &cli.LocalContext{SocketPath: socketPath},
	}
	return &cli.CommonFlags{
		OutputFormat: format,
		NoColor:      true,
		GetConfig:    func() (*cli.Config, error) { return cli.DefaultConfig(), nil },
		GetContext:   func() (*cli.Context, error) { return cliContext, nil },
	}
}

// brokenContextFlags makes cli.NewBaseCommand fail.
func brokenContextFlags() *cli.CommonFlags {
	return &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
		GetConfig:    func() (*cli.Config, error) { return cli.DefaultConfig(), nil },
		GetContext:   func() (*cli.Context, error) { return nil, testContextError{} },
	}
}

func writeSecretsConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// decodeJSONOutput decodes the JSON document that follows the
// [INFO]-prefixed progress lines in out.
func decodeJSONOutput(t *testing.T, out string, v any) {
	t.Helper()
	start := strings.Index(out, "{")
	require.GreaterOrEqual(t, start, 0, out)
	require.NoError(t, json.NewDecoder(strings.NewReader(out[start:])).Decode(v), out)
}

const mixedSecretsYAML = `db_password: env://BS_TEST_DB_PASSWORD
api_key: kms://config/api/key
remote_token: remote-kms://vault/token
device_secret: idevid://slot/1
plain: hello
`

func TestRunSecretsStatus_TableCountsWarnsAndMasks(t *testing.T) {
	flags := newSocketFlags(t, cli.OutputFormatTable, nil)
	path := writeSecretsConfig(t, mixedSecretsYAML)

	var err error
	out := captureStdout(t, func() {
		err = runSecretsStatus(flags, &secretsStatusFlags{configPath: path, showURIs: true})
	})
	require.NoError(t, err)

	for _, want := range []string{
		"Configuration: " + path,
		"Total secrets: 4",
		"KMS managed: 1",
		"Environment: 1",
		"Remote KMS: 1",
		"Unknown scheme: 1",
		"[INFO] Secret Locations",
		"kms://config/api/***",
		"env://***",
		"[WARNING] 1 secret(s) with unknown scheme may not resolve correctly",
		"[INFO] 2 secret(s) could be migrated to local KMS for unified management",
	} {
		assert.Contains(t, out, want)
	}
	assert.NotContains(t, out, testSecretEnv, "secret locations must mask the URI")
}

func TestRunSecretsStatus_JSONGroupsBySchemeWithPaths(t *testing.T) {
	flags := newSocketFlags(t, cli.OutputFormatJSON, nil)
	path := writeSecretsConfig(t, mixedSecretsYAML)

	var err error
	out := captureStdout(t, func() {
		err = runSecretsStatus(flags, &secretsStatusFlags{configPath: path, showURIs: true})
	})
	require.NoError(t, err)

	var got struct {
		ConfigPath string `json:"config_path"`
		Summary    struct {
			TotalSecrets int `json:"total_secrets"`
			KMSManaged   int `json:"kms_managed"`
			Environment  int `json:"environment"`
			RemoteKMS    int `json:"remote_kms"`
			Unknown      int `json:"unknown"`
		} `json:"summary"`
		Schemes []struct {
			Name      string   `json:"name"`
			Count     int      `json:"count"`
			Available bool     `json:"available"`
			Paths     []string `json:"paths"`
		} `json:"schemes"`
	}
	decodeJSONOutput(t, out, &got)

	assert.Equal(t, path, got.ConfigPath)
	assert.Equal(t, 4, got.Summary.TotalSecrets)
	assert.Equal(t, 1, got.Summary.KMSManaged)
	assert.Equal(t, 1, got.Summary.Environment)
	assert.Equal(t, 1, got.Summary.RemoteKMS)
	assert.Equal(t, 1, got.Summary.Unknown)

	byName := make(map[string][]string)
	available := make(map[string]bool)
	for _, s := range got.Schemes {
		assert.Equal(t, len(s.Paths), s.Count, s.Name)
		byName[s.Name] = s.Paths
		available[s.Name] = s.Available
	}
	assert.Equal(t, map[string][]string{
		"env":        {"db_password"},
		"kms":        {"api_key"},
		"remote-kms": {"remote_token"},
		"idevid":     {"device_secret"},
	}, byName)
	assert.False(t, available["idevid"])
	assert.True(t, available["env"])
}

func TestRunSecretsStatus_Errors(t *testing.T) {
	t.Run("config path required", func(t *testing.T) {
		err := runSecretsStatus(brokenContextFlags(), &secretsStatusFlags{})
		assert.ErrorIs(t, err, ErrConfigPathRequired{})
	})
	t.Run("base command fails", func(t *testing.T) {
		err := runSecretsStatus(brokenContextFlags(), &secretsStatusFlags{configPath: "x.yaml"})
		assert.ErrorAs(t, err, new(testContextError))
	})
	t.Run("config unreadable", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatTable, nil)
		missing := filepath.Join(t.TempDir(), "missing.yaml")
		err := runSecretsStatus(flags, &secretsStatusFlags{configPath: missing})
		var readErr ErrConfigFileReadFailed
		require.ErrorAs(t, err, &readErr)
		assert.Equal(t, missing, readErr.Path)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestRunSecretsVerify_DryRunChecksResolverAvailability(t *testing.T) {
	flags := newSocketFlags(t, cli.OutputFormatTable, nil)
	path := writeSecretsConfig(t, "db_password: env://BS_TEST_DB_PASSWORD\ndevice_secret: idevid://slot/1\n")

	var err error
	out := captureStdout(t, func() {
		err = runSecretsVerify(flags, &secretsVerifyFlags{configPath: path, dryRun: true})
	})

	assert.Equal(t, ErrSecretVerificationFailed{FailedCount: 1, TotalCount: 2}, err)
	assert.Contains(t, out, "[SUCCESS] OK: db_password")
	assert.Contains(t, out, "[ERROR] FAILED: device_secret - resolver not available")
	assert.Contains(t, out, "[ERROR] 1 of 2 secret(s) failed verification")
}

func TestRunSecretsVerify_ResolvesEnvSecrets(t *testing.T) {
	t.Setenv(testSecretEnv, testSecretValue)
	path := writeSecretsConfig(t, "db_password: env://BS_TEST_DB_PASSWORD\n")

	t.Run("table masks nothing and reports success", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatTable, nil)
		var err error
		out := captureStdout(t, func() {
			err = runSecretsVerify(flags, &secretsVerifyFlags{configPath: path})
		})
		require.NoError(t, err)
		assert.Contains(t, out, "[SUCCESS] OK: db_password")
		assert.Contains(t, out, "[SUCCESS] All 1 secret(s) verified successfully")
		assert.NotContains(t, out, testSecretValue)
	})

	t.Run("json shows the value only with showSecrets", func(t *testing.T) {
		for _, show := range []bool{true, false} {
			flags := newSocketFlags(t, cli.OutputFormatJSON, nil)
			var err error
			out := captureStdout(t, func() {
				err = runSecretsVerify(flags, &secretsVerifyFlags{configPath: path, showSecrets: show})
			})
			require.NoError(t, err)

			var got struct {
				DryRun   bool `json:"dry_run"`
				Total    int  `json:"total_secrets"`
				Verified int  `json:"verified"`
				Failed   int  `json:"failed"`
				Results  []struct {
					Path    string `json:"path"`
					Scheme  string `json:"scheme"`
					Success bool   `json:"success"`
					Value   string `json:"value"`
				} `json:"results"`
			}
			decodeJSONOutput(t, out, &got)
			assert.False(t, got.DryRun)
			assert.Equal(t, 1, got.Total)
			assert.Equal(t, 1, got.Verified)
			assert.Equal(t, 0, got.Failed)
			require.Len(t, got.Results, 1)
			assert.Equal(t, "db_password", got.Results[0].Path)
			assert.Equal(t, "env", got.Results[0].Scheme)
			assert.True(t, got.Results[0].Success)
			if show {
				assert.Equal(t, testSecretValue, got.Results[0].Value)
			} else {
				assert.Empty(t, got.Results[0].Value)
			}
		}
	})
}

func TestRunSecretsVerify_Failures(t *testing.T) {
	t.Setenv(testSecretEnv, testSecretValue)

	t.Run("fail fast stops at the first unresolvable secret", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatTable, nil)
		path := writeSecretsConfig(t, "db_password: env://BS_TEST_DB_PASSWORD\napi_key: kms://config/api/key\n")
		var err error
		out := captureStdout(t, func() {
			err = runSecretsVerify(flags, &secretsVerifyFlags{configPath: path, failFast: true})
		})
		assert.Equal(t, ErrSecretVerificationFailed{FailedCount: 1, TotalCount: 2}, err)
		assert.Contains(t, out, "[ERROR] FAILED: api_key - "+ErrSecretsNotImplemented{}.Error())
		assert.NotContains(t, out, "OK: db_password", "kms:// is scanned first, so fail-fast stops before env")
	})

	t.Run("json reports the resolution error", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatJSON, nil)
		path := writeSecretsConfig(t, "token: env://BS_TEST_UNSET_SECRET\n")
		var err error
		out := captureStdout(t, func() {
			err = runSecretsVerify(flags, &secretsVerifyFlags{configPath: path})
		})
		assert.Equal(t, ErrSecretVerificationFailed{FailedCount: 1, TotalCount: 1}, err)

		var got struct {
			Failed  int `json:"failed"`
			Results []struct {
				Success bool   `json:"success"`
				Error   string `json:"error"`
			} `json:"results"`
		}
		decodeJSONOutput(t, out, &got)
		assert.Equal(t, 1, got.Failed)
		require.Len(t, got.Results, 1)
		assert.False(t, got.Results[0].Success)
		assert.Equal(t, corebootstrap.ErrEnvVarNotFound{Name: testUnsetEnv}.Error(), got.Results[0].Error)
	})

	t.Run("no secrets", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatTable, nil)
		path := writeSecretsConfig(t, "plain: hello\n")
		var err error
		out := captureStdout(t, func() {
			err = runSecretsVerify(flags, &secretsVerifyFlags{configPath: path})
		})
		require.NoError(t, err)
		assert.Contains(t, out, "[INFO] No secret URIs found in configuration")
	})

	t.Run("config path required", func(t *testing.T) {
		err := runSecretsVerify(brokenContextFlags(), &secretsVerifyFlags{})
		assert.ErrorIs(t, err, ErrConfigPathRequired{})
	})

	t.Run("base command fails", func(t *testing.T) {
		err := runSecretsVerify(brokenContextFlags(), &secretsVerifyFlags{configPath: "x.yaml"})
		assert.ErrorAs(t, err, new(testContextError))
	})

	t.Run("config unreadable", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatTable, nil)
		err := runSecretsVerify(flags, &secretsVerifyFlags{configPath: filepath.Join(t.TempDir(), "missing.yaml")})
		assert.ErrorAs(t, err, new(ErrConfigFileReadFailed))
	})
}

func TestRunSecretsResolve_EnvSecret(t *testing.T) {
	t.Setenv(testSecretEnv, testSecretValue)
	uri := "env://" + testSecretEnv

	t.Run("masked table", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatTable, nil)
		var err error
		out := captureStdout(t, func() {
			err = runSecretsResolve(flags, uri, &secretsResolveFlags{masked: true})
		})
		require.NoError(t, err)
		assert.Contains(t, out, "[SUCCESS] Secret resolved successfully")
		assert.Contains(t, out, "URI: env://***")
		assert.Contains(t, out, "Scheme: env")
		assert.Contains(t, out, "Length: 12 bytes")
		assert.Contains(t, out, "Value: s3****ue")
		assert.Contains(t, out, "[INFO] Use --raw to show the full secret value")
		assert.NotContains(t, out, testSecretValue)
	})

	t.Run("raw table", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatTable, nil)
		var err error
		out := captureStdout(t, func() {
			err = runSecretsResolve(flags, uri, &secretsResolveFlags{masked: true, raw: true})
		})
		require.NoError(t, err)
		assert.Contains(t, out, "Value: "+testSecretValue)
		assert.NotContains(t, out, "Use --raw")
	})

	t.Run("json", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatJSON, nil)
		var err error
		out := captureStdout(t, func() {
			err = runSecretsResolve(flags, uri, &secretsResolveFlags{masked: true})
		})
		require.NoError(t, err)

		var got struct {
			URI      string `json:"uri"`
			Scheme   string `json:"scheme"`
			Resolved bool   `json:"resolved"`
			Value    string `json:"value"`
			Length   int    `json:"length"`
			Masked   bool   `json:"masked"`
		}
		decodeJSONOutput(t, out, &got)
		assert.Equal(t, "env://***", got.URI)
		assert.Equal(t, "env", got.Scheme)
		assert.True(t, got.Resolved)
		assert.Equal(t, "s3****ue", got.Value)
		assert.Equal(t, len(testSecretValue), got.Length)
		assert.True(t, got.Masked)
	})
}

func TestRunSecretsResolve_Errors(t *testing.T) {
	t.Run("uri required", func(t *testing.T) {
		err := runSecretsResolve(brokenContextFlags(), "", &secretsResolveFlags{})
		assert.ErrorIs(t, err, ErrSecretURIRequired{})
	})
	t.Run("unknown scheme rejected before connecting", func(t *testing.T) {
		err := runSecretsResolve(brokenContextFlags(), "http://example/secret", &secretsResolveFlags{})
		var invalid ErrInvalidSecretURI
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, "http://example/secret", invalid.URI)
	})
	t.Run("base command fails", func(t *testing.T) {
		err := runSecretsResolve(brokenContextFlags(), "env://X", &secretsResolveFlags{})
		assert.ErrorAs(t, err, new(testContextError))
	})
	t.Run("idevid has no resolver", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatTable, nil)
		err := runSecretsResolve(flags, "idevid://slot/1", &secretsResolveFlags{})
		assert.Equal(t, ErrResolverNotAvailable{Scheme: "idevid"}, err)
	})

	tests := []struct {
		name    string
		uri     string
		masked  string
		wantErr error
	}{
		{"kms is not implemented", "kms://config/api", "kms://config/api/***", ErrSecretsNotImplemented{}},
		{"remote kms cannot resolve", "remote-kms://vault/token", "remote-kms://vault/token/***", ErrResolverNotAvailable{Scheme: "remote-kms"}},
		{"unset env var", "env://" + testUnsetEnv, "env://***", corebootstrap.ErrEnvVarNotFound{Name: testUnsetEnv}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := newSocketFlags(t, cli.OutputFormatTable, nil)
			err := runSecretsResolve(flags, tt.uri, &secretsResolveFlags{})
			var failed ErrSecretResolutionFailed
			require.ErrorAs(t, err, &failed)
			assert.Equal(t, tt.masked, failed.URI)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestResolveSecretValue(t *testing.T) {
	t.Setenv(testSecretEnv, testSecretValue)

	value, err := resolveSecretValue(context.Background(), nil, "env://"+testSecretEnv)
	require.NoError(t, err)
	assert.Equal(t, []byte(testSecretValue), value)

	tests := []struct {
		uri     string
		wantErr error
	}{
		{"kms://config/api", ErrSecretsNotImplemented{}},
		{"env://" + testUnsetEnv, corebootstrap.ErrEnvVarNotFound{Name: testUnsetEnv}},
		{"remote-kms://vault/token", ErrResolverNotAvailable{Scheme: "remote-kms"}},
		{"idevid://slot/1", ErrResolverNotAvailable{Scheme: "idevid"}},
		{"plain-value", ErrInvalidSecretURI{URI: "plain-value", Reason: "unknown scheme"}},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			value, err := resolveSecretValue(context.Background(), nil, tt.uri)
			assert.Nil(t, value)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func TestResolveSecretByScheme(t *testing.T) {
	t.Setenv(testSecretEnv, testSecretValue)
	secretFile := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(secretFile, []byte("pem-bytes"), 0o600))

	for _, tt := range []struct {
		uri, scheme, want string
	}{
		{"env://" + testSecretEnv, "env", testSecretValue},
		{"file://" + secretFile, "file", "pem-bytes"},
	} {
		value, err := resolveSecretByScheme(context.Background(), tt.uri, tt.scheme)
		require.NoError(t, err, tt.uri)
		assert.Equal(t, tt.want, string(value))
	}

	missing := filepath.Join(t.TempDir(), "missing.pem")
	_, err := resolveSecretByScheme(context.Background(), "file://"+missing, "file")
	var readErr ErrFileReadFailed
	require.ErrorAs(t, err, &readErr)
	assert.Equal(t, missing, readErr.Path)
	assert.ErrorIs(t, err, os.ErrNotExist)

	tests := []struct {
		uri, scheme string
		wantErr     error
	}{
		{"env://" + testUnsetEnv, "env", ErrEnvVarNotSet{Name: testUnsetEnv}},
		{"kms://config/api", "kms", ErrAlreadyKMSManaged{Path: "kms://config/api"}},
		{"remote-kms://vault/token", "remote-kms", ErrResolverNotAvailable{Scheme: "remote-kms"}},
		{"idevid://slot/1", "idevid", ErrResolverNotAvailable{Scheme: "idevid"}},
		{"ftp://host/x", "unknown", ErrInvalidSecretURI{URI: "ftp://host/x", Reason: "unknown scheme: unknown"}},
	}
	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			value, err := resolveSecretByScheme(context.Background(), tt.uri, tt.scheme)
			assert.Nil(t, value)
			assert.Equal(t, tt.wantErr, err)
		})
	}
}

func TestIsResolverAvailable(t *testing.T) {
	for scheme, want := range map[string]bool{
		"kms": true, "env": true, "autogen": true, "remote-kms": true, "encrypted": true,
		"idevid": false, "unknown": false, "": false,
	} {
		assert.Equal(t, want, isResolverAvailable(scheme), scheme)
	}
}

func TestJoinMACs(t *testing.T) {
	assert.Equal(t, "", joinMACs(nil))
	assert.Equal(t, "", joinMACs([]string{}))
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", joinMACs([]string{"aa:bb:cc:dd:ee:ff"}))
	assert.Equal(t, "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:02", joinMACs([]string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}))
}

// migrateFixture writes a config holding an env secret, a file secret and an
// already-KMS-managed secret, and returns the config path and its content.
func migrateFixture(t *testing.T) (string, string) {
	t.Helper()
	t.Setenv(testSecretEnv, testSecretValue)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyFile, []byte("pem-bytes"), 0o600))

	content := "db_password: env://" + testSecretEnv + "\n" +
		"tls_key: file://" + keyFile + "\n" +
		"api_key: kms://config/api/key\n"
	path := filepath.Join(dir, "bootstrap.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path, content
}

func readYAMLMap(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]string
	require.NoError(t, yaml.Unmarshal(data, &m))
	return m
}

func backupFiles(t *testing.T, configPath string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(configPath), "*backup*"))
	require.NoError(t, err)
	return matches
}

func TestRunSecretsMigrate_MigratesBacksUpAndVerifies(t *testing.T) {
	path, original := migrateFixture(t)
	kms := &fakeKMSServer{}
	flags := newSocketFlags(t, cli.OutputFormatTable, kms)

	var err error
	out := captureStdout(t, func() {
		err = runSecretsMigrate(flags, &secretsMigrateFlags{configPath: path, keyID: testMigrateKey})
	})
	require.NoError(t, err, out)

	assert.Equal(t, int32(4), kms.calls.Load(), "two stores and two verifications")
	assert.Equal(t, map[string]string{
		"db_password": "kms://config/db_password",
		"tls_key":     "kms://config/tls_key",
		"api_key":     "kms://config/api/key",
	}, readYAMLMap(t, path))

	backups := backupFiles(t, path)
	require.Len(t, backups, 1)
	backup, err := os.ReadFile(backups[0])
	require.NoError(t, err)
	assert.Equal(t, original, string(backup))

	for _, want := range []string{
		"[INFO] Found 3 secret(s) in " + path,
		"[INFO]   SKIP: api_key (already KMS-managed)",
		"[SUCCESS]   OK: db_password (env)",
		"[SUCCESS]   OK: tls_key (file)",
		"[INFO] Phase 2: Migrating 2 secret(s) to KMS...",
		"[SUCCESS]   OK: db_password -> kms://config/db_password/***",
		"[SUCCESS] Backup created: " + backups[0],
		"[SUCCESS] Updated 2 secret reference(s) in configuration",
		"Stored in KMS: 2",
		"Verified: 2",
		"Skipped (already KMS): 1",
		"[SUCCESS] Migration completed successfully",
	} {
		assert.Contains(t, out, want)
	}
	assert.NotContains(t, out, testSecretValue)
}

func TestRunSecretsMigrate_NoBackup(t *testing.T) {
	path, _ := migrateFixture(t)
	flags := newSocketFlags(t, cli.OutputFormatTable, &fakeKMSServer{})

	var err error
	out := captureStdout(t, func() {
		err = runSecretsMigrate(flags, &secretsMigrateFlags{configPath: path, keyID: testMigrateKey, noBackup: true})
	})
	require.NoError(t, err, out)
	assert.Empty(t, backupFiles(t, path))
	assert.NotContains(t, out, "Phase 3")
	assert.Equal(t, "kms://config/db_password", readYAMLMap(t, path)["db_password"])
}

func TestRunSecretsMigrate_DryRunChangesNothing(t *testing.T) {
	t.Run("table", func(t *testing.T) {
		path, original := migrateFixture(t)
		kms := &fakeKMSServer{}
		flags := newSocketFlags(t, cli.OutputFormatTable, kms)

		var err error
		out := captureStdout(t, func() {
			err = runSecretsMigrate(flags, &secretsMigrateFlags{configPath: path, keyID: testMigrateKey, dryRun: true})
		})
		require.NoError(t, err)
		assert.Contains(t, out, "[INFO] DRY RUN - No changes will be made")
		assert.Contains(t, out, "MIGRATE")
		assert.Contains(t, out, "SKIP (already KMS)")
		assert.Contains(t, out, "kms://config/tls_key/***")
		assertUnchanged(t, path, original, kms)
	})

	t.Run("json with a forced resolve failure", func(t *testing.T) {
		path, original := migrateFixture(t)
		content := original + "token: env://" + testUnsetEnv + "\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		kms := &fakeKMSServer{}
		flags := newSocketFlags(t, cli.OutputFormatJSON, kms)

		var err error
		out := captureStdout(t, func() {
			err = runSecretsMigrate(flags, &secretsMigrateFlags{configPath: path, keyID: testMigrateKey, dryRun: true, force: true})
		})
		require.NoError(t, err)
		assertUnchanged(t, path, content, kms)

		var got struct {
			DryRun  bool `json:"dry_run"`
			Changes []struct {
				Path     string `json:"path"`
				Scheme   string `json:"scheme"`
				NewURI   string `json:"new_uri"`
				Resolved bool   `json:"resolved"`
				Skipped  bool   `json:"skipped"`
				Error    string `json:"error"`
			} `json:"changes"`
		}
		decodeJSONOutput(t, out, &got)
		assert.True(t, got.DryRun)

		changes := make(map[string]string)
		for _, c := range got.Changes {
			switch {
			case c.Skipped:
				changes[c.Path] = "skipped"
			case c.Error != "":
				changes[c.Path] = c.Error
			default:
				changes[c.Path] = c.NewURI
			}
		}
		assert.Equal(t, map[string]string{
			"api_key":     "skipped",
			"db_password": "kms://config/db_password",
			"tls_key":     "kms://config/tls_key",
			"token":       ErrEnvVarNotSet{Name: testUnsetEnv}.Error(),
		}, changes)
	})
}

func assertUnchanged(t *testing.T, path, original string, kms *fakeKMSServer) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, original, string(data))
	assert.Empty(t, backupFiles(t, path))
	assert.Equal(t, int32(0), kms.calls.Load())
}

func TestRunSecretsMigrate_NothingToMigrate(t *testing.T) {
	tests := []struct {
		name, content, want string
	}{
		{"no secrets", "plain: hello\n", "[INFO] No secret URIs found in configuration"},
		{"all kms", "api_key: kms://config/api/key\n", "[INFO] No secrets to migrate (all secrets are already KMS-managed or failed to resolve)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeSecretsConfig(t, tt.content)
			kms := &fakeKMSServer{}
			flags := newSocketFlags(t, cli.OutputFormatTable, kms)
			var err error
			out := captureStdout(t, func() {
				err = runSecretsMigrate(flags, &secretsMigrateFlags{configPath: path, keyID: testMigrateKey})
			})
			require.NoError(t, err)
			assert.Contains(t, out, tt.want)
			assertUnchanged(t, path, tt.content, kms)
		})
	}
}

func TestRunSecretsMigrate_Failures(t *testing.T) {
	t.Run("resolve failure without force", func(t *testing.T) {
		content := "token: env://" + testUnsetEnv + "\n"
		path := writeSecretsConfig(t, content)
		kms := &fakeKMSServer{}
		flags := newSocketFlags(t, cli.OutputFormatTable, kms)
		var err error
		out := captureStdout(t, func() {
			err = runSecretsMigrate(flags, &secretsMigrateFlags{configPath: path, keyID: testMigrateKey})
		})
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "1 secret(s) failed to resolve; use --force to continue anyway", msg.Msg)
		assert.ErrorAs(t, err, new(ErrMigrationFailed))
		assert.Contains(t, out, "[ERROR]   FAIL: token - "+ErrEnvVarNotSet{Name: testUnsetEnv}.Error())
		assertUnchanged(t, path, content, kms)
	})

	t.Run("store failure without force", func(t *testing.T) {
		path, original := migrateFixture(t)
		kms := &fakeKMSServer{failPlaintext: testSecretValue}
		flags := newSocketFlags(t, cli.OutputFormatTable, kms)
		var err error
		captureStdout(t, func() {
			err = runSecretsMigrate(flags, &secretsMigrateFlags{configPath: path, keyID: testMigrateKey})
		})
		var msg *MessageError
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "1 secret(s) failed to store in KMS", msg.Msg)
		assert.Equal(t, original, readFile(t, path))
		assert.Empty(t, backupFiles(t, path))
	})

	t.Run("store failure with force stores nothing", func(t *testing.T) {
		t.Setenv(testSecretEnv, testSecretValue)
		content := "db_password: env://" + testSecretEnv + "\n"
		path := writeSecretsConfig(t, content)
		kms := &fakeKMSServer{failPlaintext: testSecretValue}
		flags := newSocketFlags(t, cli.OutputFormatTable, kms)
		var err error
		out := captureStdout(t, func() {
			err = runSecretsMigrate(flags, &secretsMigrateFlags{configPath: path, keyID: testMigrateKey, force: true})
		})
		require.NoError(t, err)
		assert.Contains(t, out, "[ERROR]   FAIL: db_password - ")
		assert.Contains(t, out, "[WARNING] No secrets were stored in KMS")
		assert.Equal(t, content, readFile(t, path))
	})

	t.Run("verification failure", func(t *testing.T) {
		t.Setenv(testSecretEnv, testSecretValue)
		path := writeSecretsConfig(t, "db_password: env://"+testSecretEnv+"\n")
		kms := &fakeKMSServer{failPlaintext: "verification-test"}
		flags := newSocketFlags(t, cli.OutputFormatJSON, kms)
		var err error
		out := captureStdout(t, func() {
			err = runSecretsMigrate(flags, &secretsMigrateFlags{configPath: path, keyID: testMigrateKey})
		})
		assert.Equal(t, ErrSecretVerificationFailed{FailedCount: 1, TotalCount: 1}, err)

		summary := out[strings.LastIndex(out, "{\n"):]
		var got struct {
			BackupPath string `json:"backup_path"`
			Stored     int    `json:"stored_in_kms"`
			Verified   int    `json:"verified"`
			Failed     int    `json:"failed"`
			Success    bool   `json:"success"`
		}
		decodeJSONOutput(t, summary, &got)
		assert.Equal(t, 1, got.Stored)
		assert.Equal(t, 0, got.Verified)
		assert.Equal(t, 1, got.Failed)
		assert.False(t, got.Success)
		assert.NotEmpty(t, got.BackupPath)
		assert.Equal(t, "kms://config/db_password", readYAMLMap(t, path)["db_password"])
	})

	t.Run("config path required", func(t *testing.T) {
		err := runSecretsMigrate(brokenContextFlags(), &secretsMigrateFlags{})
		assert.ErrorIs(t, err, ErrConfigPathRequired{})
	})

	t.Run("base command fails", func(t *testing.T) {
		err := runSecretsMigrate(brokenContextFlags(), &secretsMigrateFlags{configPath: "x.yaml"})
		assert.ErrorAs(t, err, new(testContextError))
	})

	t.Run("config unreadable", func(t *testing.T) {
		flags := newSocketFlags(t, cli.OutputFormatTable, nil)
		err := runSecretsMigrate(flags, &secretsMigrateFlags{configPath: filepath.Join(t.TempDir(), "missing.yaml")})
		assert.ErrorAs(t, err, new(ErrConfigFileReadFailed))
	})
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

func TestStoreAndVerifySecrets_ClientEdgeCases(t *testing.T) {
	entries := func() []migrationEntry {
		return []migrationEntry{
			{path: "db_password", scheme: "env", resolved: true, value: []byte("v"), kmsPath: "kms://config/db_password"},
			{path: "api_key", scheme: "kms", alreadyKMS: true},
		}
	}

	t.Run("nil client fails every entry", func(t *testing.T) {
		var stored, storeFailed, verified, verifyFailed int
		out := captureStdout(t, func() {
			printer := cli.NewPrinter(cli.OutputFormatTable, true)
			stored, storeFailed = storeSecretsInKMS(context.Background(), nil, entries(), testMigrateKey, printer)
			verified, verifyFailed = verifyMigratedSecrets(context.Background(), nil, entries(), testMigrateKey, printer)
		})
		assert.Equal(t, []int{0, 2, 0, 2}, []int{stored, storeFailed, verified, verifyFailed})
		assert.Equal(t, 2, strings.Count(out, "[ERROR] KMS client not available"))
	})

	t.Run("nil result is a failure", func(t *testing.T) {
		client := kmssvc.NewClientFromGRPC(nilResultKMSClient{})
		list := entries()
		var stored, storeFailed, verified, verifyFailed int
		out := captureStdout(t, func() {
			printer := cli.NewPrinter(cli.OutputFormatTable, true)
			stored, storeFailed = storeSecretsInKMS(context.Background(), client, list, testMigrateKey, printer)
			verified, verifyFailed = verifyMigratedSecrets(context.Background(), client, entries(), testMigrateKey, printer)
		})
		assert.Equal(t, []int{0, 1, 0, 1}, []int{stored, storeFailed, verified, verifyFailed})
		assert.Equal(t, "encryption returned nil result", list[0].errorMsg)
		assert.Contains(t, out, "[ERROR]   FAIL: db_password - encryption returned nil result")
		assert.Contains(t, out, "[ERROR]   FAIL: db_password - verification returned nil result")
	})
}

func TestBootstrapErrorMessages(t *testing.T) {
	cause := errors.New("boom")

	wrapped := &WrappedError{Msg: "outer", Err: cause}
	assert.Equal(t, "outer: boom", wrapped.Error())
	assert.ErrorIs(t, wrapped, cause)

	assert.Equal(t, "plain message", (&MessageError{Msg: "plain message"}).Error())
	assert.Contains(t, ErrBootstrapShutdownStuck{Grace: 5e9}.Error(), "did not shut down within 5s of cancellation")

	dryRun := ErrPXEDryRunFailed{Cause: cause}
	assert.Equal(t, "bootstrap dry-run failed: boom", dryRun.Error())
	assert.ErrorIs(t, dryRun, cause)

	probe := &ErrProbeFailed{Cause: cause}
	assert.Equal(t, "bootstrap probe: boom", probe.Error())
	assert.ErrorIs(t, probe, cause)

	dump := ErrResolveDumpFailed{Path: "/tmp/cp-01.yaml", Cause: cause}
	assert.Equal(t, "bootstrap resolve: write /tmp/cp-01.yaml: boom", dump.Error())
	assert.ErrorIs(t, dump, cause)

	pending := &PendingBootstrapBackendError{Mode: "dane"}
	assert.Equal(t, "bootstrap dane is owned by xkms; invoke via 'xkmsctl bootstrap dane' until the platform bridge ships", pending.Error())
}
