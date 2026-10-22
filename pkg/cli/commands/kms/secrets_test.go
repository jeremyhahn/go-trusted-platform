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

package kms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// fakeSecretsClient is an in-memory quicbaassdk.SecretsClient. Each method
// returns err when it is set, and records the request it was given.
type fakeSecretsClient struct {
	err error

	storeReq    *secretsclient.StoreSecretRequest
	getPath     string
	getOpts     int
	listPrefix  string
	deletePath  string
	rotateReq   *secretsclient.RotateSecretRequest
	versionReq  *secretsclient.GetSecretVersionRequest
	versionsID  string
	rollbackReq *secretsclient.RollbackSecretRequest
	statusReq   *secretsclient.UpdateSecretStatusRequest
	policyReq   *secretsclient.SetRotationPolicyRequest
	policyID    string

	secrets map[string]*secretsclient.Secret
	paths   []string
	policy  *secretsclient.RotationPolicy
}

func (f *fakeSecretsClient) Store(_ context.Context, req *secretsclient.StoreSecretRequest) (*secretsclient.StoreSecretResponse, error) {
	f.storeReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.StoreSecretResponse{Version: 1}, nil
}

func (f *fakeSecretsClient) Get(_ context.Context, path string, opts ...secretsclient.GetOption) (*secretsclient.Secret, error) {
	f.getPath = path
	f.getOpts = len(opts)
	if f.err != nil {
		return nil, f.err
	}
	return f.secrets[path], nil
}

func (f *fakeSecretsClient) List(_ context.Context, prefix string) (*secretsclient.ListSecretsResponse, error) {
	f.listPrefix = prefix
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.ListSecretsResponse{Paths: f.paths}, nil
}

func (f *fakeSecretsClient) Delete(_ context.Context, path string) error {
	f.deletePath = path
	return f.err
}

func (f *fakeSecretsClient) Ensure(_ context.Context, _ *secretsclient.EnsureSecretRequest) (*secretsclient.EnsureSecretResponse, error) {
	return nil, f.err
}

func (f *fakeSecretsClient) GetVersion(_ context.Context, req *secretsclient.GetSecretVersionRequest) (*secretsclient.SecretVersionInfo, error) {
	f.versionReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.SecretVersionInfo{SecretID: req.SecretID, Version: req.Version, Data: []byte("v"), CreatedBy: "op"}, nil
}

func (f *fakeSecretsClient) ListVersions(_ context.Context, secretID string) (*secretsclient.ListSecretVersionsResponse, error) {
	f.versionsID = secretID
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.ListSecretVersionsResponse{Versions: []secretsclient.SecretVersionInfo{
		{SecretID: secretID, Version: 1, Data: []byte("never printed")},
		{SecretID: secretID, Version: 2},
	}}, nil
}

func (f *fakeSecretsClient) Rotate(_ context.Context, req *secretsclient.RotateSecretRequest) (*secretsclient.RotateSecretResponse, error) {
	f.rotateReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.RotateSecretResponse{SecretID: req.SecretID, OldVersion: 1, NewVersion: 2}, nil
}

func (f *fakeSecretsClient) Rollback(_ context.Context, req *secretsclient.RollbackSecretRequest) (*secretsclient.RollbackSecretResponse, error) {
	f.rollbackReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &secretsclient.RollbackSecretResponse{SecretID: req.SecretID, NewVersion: 3}, nil
}

func (f *fakeSecretsClient) UpdateStatus(_ context.Context, req *secretsclient.UpdateSecretStatusRequest) error {
	f.statusReq = req
	return f.err
}

func (f *fakeSecretsClient) SetRotationPolicy(_ context.Context, req *secretsclient.SetRotationPolicyRequest) error {
	f.policyReq = req
	return f.err
}

func (f *fakeSecretsClient) GetRotationPolicy(_ context.Context, secretID string) (*secretsclient.RotationPolicy, error) {
	f.policyID = secretID
	if f.err != nil {
		return nil, f.err
	}
	return f.policy, nil
}

var _ quicbaassdk.SecretsClient = (*fakeSecretsClient)(nil)

// errFakeSecrets is the error a failing fakeSecretsClient returns.
var errFakeSecrets = errors.New("secrets backend down")

// runSecretsJSON runs a verb with a JSON printer and decodes what it printed.
func runSecretsJSON(t *testing.T, run func(printer *cli.Printer) error) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, run(cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &buf)))
	out := map[string]any{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	return out
}

// requireSecretOperationFailed asserts err wraps the fake's error for op.
func requireSecretOperationFailed(t *testing.T, err error, op string) {
	t.Helper()
	require.ErrorIs(t, err, errFakeSecrets)
	var opErr ErrSecretOperationFailed
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, op, opErr.Operation)
}

func TestOpenSecretsClient(t *testing.T) {
	t.Run("factory override", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		restore := SetSecretsClientFactory(func(base *cli.BaseCommand) (quicbaassdk.SecretsClient, error) {
			return fake, nil
		})
		defer restore()

		client, err := openSecretsClient(nil)
		require.NoError(t, err)
		assert.Same(t, fake, client)
	})

	t.Run("factory error", func(t *testing.T) {
		restore := SetSecretsClientFactory(func(base *cli.BaseCommand) (quicbaassdk.SecretsClient, error) {
			return nil, errFakeSecrets
		})
		defer restore()

		_, err := openSecretsClient(nil)
		assert.ErrorIs(t, err, errFakeSecrets)
	})
}

func TestExecuteSecretsStore(t *testing.T) {
	ctx := context.Background()

	t.Run("stores value, description and tags", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsStore(ctx, fake, p, cli.OutputFormatJSON, "db/pw",
				secretStoreOptions{Value: "AAEC/w==", Base64: true, Description: "d", Tags: []string{"env=prod"}})
		})
		assert.Equal(t, "db/pw", out["name"])
		assert.Equal(t, float64(1), out["version"])
		assert.Equal(t, "db/pw", fake.storeReq.Path)
		assert.Equal(t, []byte{0, 1, 2, 255}, fake.storeReq.Data["value"])
		assert.Equal(t, "d", fake.storeReq.Data["description"])
		assert.Equal(t, map[string]string{"env": "prod"}, fake.storeReq.Metadata)
	})

	t.Run("input errors never reach the client", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		p := newTestKMSPrinter()
		assert.ErrorIs(t, executeSecretsStore(ctx, fake, p, cli.OutputFormatJSON, "", secretStoreOptions{Value: "v"}), ErrSecretNameRequired{})
		assert.ErrorIs(t, executeSecretsStore(ctx, fake, p, cli.OutputFormatJSON, "n", secretStoreOptions{}), ErrSecretValueRequired{})
		var b64Err ErrInvalidSecretValue
		assert.ErrorAs(t, executeSecretsStore(ctx, fake, p, cli.OutputFormatJSON, "n", secretStoreOptions{Value: "!!", Base64: true}), &b64Err)
		assert.ErrorIs(t, executeSecretsStore(ctx, fake, p, cli.OutputFormatJSON, "n", secretStoreOptions{Value: "v", Tags: []string{"bad"}}), ErrInvalidTagFormat{Tag: "bad"})
		assert.Nil(t, fake.storeReq)
	})

	t.Run("client error", func(t *testing.T) {
		err := executeSecretsStore(ctx, &fakeSecretsClient{err: errFakeSecrets}, newTestKMSPrinter(), cli.OutputFormatJSON, "n", secretStoreOptions{Value: "v"})
		requireSecretOperationFailed(t, err, "store")
	})

	t.Run("invalid output format", func(t *testing.T) {
		err := executeSecretsStore(ctx, &fakeSecretsClient{}, newTestKMSPrinter(), cli.OutputFormat("xml"), "n", secretStoreOptions{Value: "v"})
		assert.ErrorIs(t, err, cli.ErrInvalidOutputFormat{Format: "xml"})
	})
}

func TestExecuteSecretsGet(t *testing.T) {
	ctx := context.Background()
	created := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)

	t.Run("reads the value the REST surface stores", func(t *testing.T) {
		// The SDK returns stored []byte data as its base64 JSON text.
		fake := &fakeSecretsClient{secrets: map[string]*secretsclient.Secret{
			"db/pw": {Path: "db/pw", Version: 2, CreatedAt: created, Metadata: map[string]string{"env": "prod"},
				Data: map[string]interface{}{"value": "czNjcmV0", "description": "d"}},
		}}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsGet(ctx, fake, p, cli.OutputFormatJSON, "db/pw", 2)
		})
		assert.Equal(t, "db/pw", out["name"])
		assert.Equal(t, float64(2), out["version"])
		assert.Equal(t, "czNjcmV0", out["value"])
		assert.Equal(t, "d", out["description"])
		assert.Equal(t, 1, fake.getOpts, "--version passes WithVersion")
	})

	t.Run("table format prints the stored bytes", func(t *testing.T) {
		fake := &fakeSecretsClient{secrets: map[string]*secretsclient.Secret{
			"n": {Path: "n", Version: 1, Data: map[string]interface{}{"value": "cmF3"}},
		}}
		var buf bytes.Buffer
		require.NoError(t, executeSecretsGet(ctx, fake, cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf), cli.OutputFormatTable, "n", 0))
		assert.Contains(t, buf.String(), "raw")
		assert.NotContains(t, buf.String(), "cmF3", "the base64 text is decoded")
		assert.Zero(t, fake.getOpts, "version 0 reads the current version")
	})

	t.Run("malformed stored value", func(t *testing.T) {
		fake := &fakeSecretsClient{secrets: map[string]*secretsclient.Secret{
			"n": {Path: "n", Version: 1, Data: map[string]interface{}{"value": "not base64!"}},
		}}
		err := executeSecretsGet(ctx, fake, newTestKMSPrinter(), cli.OutputFormatJSON, "n", 0)
		var failed ErrSecretOperationFailed
		require.ErrorAs(t, err, &failed)
		assert.Equal(t, "get", failed.Operation)
		var malformed common.ErrMalformedSecretValue
		assert.ErrorAs(t, err, &malformed)
	})

	t.Run("errors", func(t *testing.T) {
		p := newTestKMSPrinter()
		assert.ErrorIs(t, executeSecretsGet(ctx, &fakeSecretsClient{}, p, cli.OutputFormatJSON, "", 0), ErrSecretNameRequired{})
		assert.ErrorIs(t, executeSecretsGet(ctx, &fakeSecretsClient{}, p, cli.OutputFormatJSON, "n", -1), ErrInvalidSecretVersion{Value: "-1"})
		requireSecretOperationFailed(t, executeSecretsGet(ctx, &fakeSecretsClient{err: errFakeSecrets}, p, cli.OutputFormatJSON, "n", 0), "get")
	})
}

func TestExecuteSecretsList(t *testing.T) {
	ctx := context.Background()

	t.Run("limit truncates and reports has_more", func(t *testing.T) {
		fake := &fakeSecretsClient{paths: []string{"a/1", "a/2", "a/3"}}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsList(ctx, fake, p, cli.OutputFormatJSON, "a/", 2, false)
		})
		assert.Equal(t, []any{"a/1", "a/2"}, out["secrets"])
		assert.Equal(t, true, out["has_more"])
		assert.Equal(t, "a/", fake.listPrefix)
	})

	t.Run("empty list prints an empty array", func(t *testing.T) {
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsList(ctx, &fakeSecretsClient{}, p, cli.OutputFormatJSON, "", 100, false)
		})
		assert.Equal(t, []any{}, out["secrets"])
		assert.Equal(t, false, out["has_more"])
	})

	t.Run("include data reads every secret", func(t *testing.T) {
		fake := &fakeSecretsClient{paths: []string{"p/x"}, secrets: map[string]*secretsclient.Secret{
			"p/x": {Path: "p/x", Version: 1, Data: map[string]interface{}{"value": "dng="}},
		}}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsList(ctx, fake, p, cli.OutputFormatJSON, "p/", 0, true)
		})
		data, ok := out["data"].([]any)
		require.True(t, ok)
		require.Len(t, data, 1)
		assert.Equal(t, "dng=", data[0].(map[string]any)["value"])
	})

	// The gRPC transport answers Get with the server's secret ID as Path,
	// which need not be the listed name; every data entry is named by the
	// path the listing returned, so a caller can match entries to names.
	t.Run("include data names each entry by its listed path", func(t *testing.T) {
		fake := &fakeSecretsClient{paths: []string{"p/x", "p/y"}, secrets: map[string]*secretsclient.Secret{
			"p/x": {Path: "server-id-1", Version: 1, Data: map[string]interface{}{"value": "dng="}},
			"p/y": {Version: 2, Data: map[string]interface{}{"value": "dnk="}},
		}}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsList(ctx, fake, p, cli.OutputFormatJSON, "p/", 0, true)
		})
		data, ok := out["data"].([]any)
		require.True(t, ok)
		require.Len(t, data, 2)
		assert.Equal(t, "p/x", data[0].(map[string]any)["name"])
		assert.Equal(t, "p/y", data[1].(map[string]any)["name"])
	})

	t.Run("errors", func(t *testing.T) {
		requireSecretOperationFailed(t, executeSecretsList(ctx, &fakeSecretsClient{err: errFakeSecrets}, newTestKMSPrinter(), cli.OutputFormatJSON, "", 0, false), "list")
	})
}

func TestExecuteSecretsDelete(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsDelete(ctx, fake, p, cli.OutputFormatJSON, "n")
		})
		assert.Equal(t, true, out["deleted"])
		assert.Equal(t, "n", fake.deletePath)
	})

	t.Run("errors", func(t *testing.T) {
		assert.ErrorIs(t, executeSecretsDelete(ctx, &fakeSecretsClient{}, newTestKMSPrinter(), cli.OutputFormatJSON, ""), ErrSecretNameRequired{})
		requireSecretOperationFailed(t, executeSecretsDelete(ctx, &fakeSecretsClient{err: errFakeSecrets}, newTestKMSPrinter(), cli.OutputFormatJSON, "n"), "delete")
	})
}

func TestExecuteSecretsRotate(t *testing.T) {
	ctx := context.Background()

	t.Run("rotates", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsRotate(ctx, fake, p, cli.OutputFormatJSON, "n", "new", false)
		})
		assert.Equal(t, float64(1), out["old_version"])
		assert.Equal(t, float64(2), out["new_version"])
		assert.Equal(t, []byte("new"), fake.rotateReq.NewData)
	})

	t.Run("errors", func(t *testing.T) {
		p := newTestKMSPrinter()
		assert.ErrorIs(t, executeSecretsRotate(ctx, &fakeSecretsClient{}, p, cli.OutputFormatJSON, "", "v", false), ErrSecretNameRequired{})
		assert.ErrorIs(t, executeSecretsRotate(ctx, &fakeSecretsClient{}, p, cli.OutputFormatJSON, "n", "", false), ErrSecretValueRequired{})
		requireSecretOperationFailed(t, executeSecretsRotate(ctx, &fakeSecretsClient{err: errFakeSecrets}, p, cli.OutputFormatJSON, "n", "v", false), "rotate")
	})
}

func TestExecuteSecretsVersion(t *testing.T) {
	ctx := context.Background()

	t.Run("reads one version", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsVersion(ctx, fake, p, cli.OutputFormatJSON, "n", 4)
		})
		assert.Equal(t, float64(4), out["version"])
		assert.Equal(t, "dg==", out["value"])
		assert.Equal(t, "op", out["created_by"])
		assert.Equal(t, &secretsclient.GetSecretVersionRequest{SecretID: "n", Version: 4}, fake.versionReq)
	})

	t.Run("errors", func(t *testing.T) {
		assert.ErrorIs(t, executeSecretsVersion(ctx, &fakeSecretsClient{}, newTestKMSPrinter(), cli.OutputFormatJSON, "", 1), ErrSecretNameRequired{})
		requireSecretOperationFailed(t, executeSecretsVersion(ctx, &fakeSecretsClient{err: errFakeSecrets}, newTestKMSPrinter(), cli.OutputFormatJSON, "n", 1), "version")
	})
}

func TestExecuteSecretsVersions(t *testing.T) {
	ctx := context.Background()

	t.Run("lists versions without values", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		var buf bytes.Buffer
		require.NoError(t, executeSecretsVersions(ctx, fake, cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &buf), cli.OutputFormatJSON, "n"))
		assert.NotContains(t, buf.String(), "never printed")
		out := map[string]any{}
		require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
		assert.Len(t, out["versions"], 2)
		assert.Equal(t, "n", fake.versionsID)
	})

	t.Run("errors", func(t *testing.T) {
		assert.ErrorIs(t, executeSecretsVersions(ctx, &fakeSecretsClient{}, newTestKMSPrinter(), cli.OutputFormatJSON, ""), ErrSecretNameRequired{})
		requireSecretOperationFailed(t, executeSecretsVersions(ctx, &fakeSecretsClient{err: errFakeSecrets}, newTestKMSPrinter(), cli.OutputFormatJSON, "n"), "versions")
	})
}

func TestExecuteSecretsRollback(t *testing.T) {
	ctx := context.Background()

	t.Run("rolls back", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsRollback(ctx, fake, p, cli.OutputFormatJSON, "n", 1)
		})
		assert.Equal(t, float64(3), out["new_version"])
		assert.Equal(t, 1, fake.rollbackReq.TargetVersion)
	})

	t.Run("errors", func(t *testing.T) {
		assert.ErrorIs(t, executeSecretsRollback(ctx, &fakeSecretsClient{}, newTestKMSPrinter(), cli.OutputFormatJSON, "", 1), ErrSecretNameRequired{})
		requireSecretOperationFailed(t, executeSecretsRollback(ctx, &fakeSecretsClient{err: errFakeSecrets}, newTestKMSPrinter(), cli.OutputFormatJSON, "n", 1), "rollback")
	})
}

func TestExecuteSecretsStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("disables", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsStatus(ctx, fake, p, cli.OutputFormatJSON, "n", secretsclient.SecretStatusDisabled)
		})
		assert.Equal(t, "disabled", out["status"])
		assert.Equal(t, secretsclient.SecretStatusDisabled, fake.statusReq.Status)
	})

	t.Run("errors", func(t *testing.T) {
		assert.ErrorIs(t, executeSecretsStatus(ctx, &fakeSecretsClient{}, newTestKMSPrinter(), cli.OutputFormatJSON, "", secretsclient.SecretStatusEnabled), ErrSecretNameRequired{})
		requireSecretOperationFailed(t, executeSecretsStatus(ctx, &fakeSecretsClient{err: errFakeSecrets}, newTestKMSPrinter(), cli.OutputFormatJSON, "n", secretsclient.SecretStatusEnabled), "status")
	})
}

func TestExecuteSecretsPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("get", func(t *testing.T) {
		fake := &fakeSecretsClient{policy: &secretsclient.RotationPolicy{Enabled: true, Interval: time.Hour, RetainVersions: 5}}
		out := runSecretsJSON(t, func(p *cli.Printer) error {
			return executeSecretsPolicyGet(ctx, fake, p, cli.OutputFormatJSON, "n")
		})
		assert.Equal(t, true, out["enabled"])
		assert.Equal(t, float64(3600), out["interval_seconds"])
		assert.Equal(t, float64(5), out["retain_versions"])
		assert.Equal(t, "n", fake.policyID)
	})

	t.Run("set", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		var buf bytes.Buffer
		opts := secretPolicyOptions{Enabled: true, Interval: 2 * time.Hour, RetainVersions: 3, RotationLambda: "gen"}
		require.NoError(t, executeSecretsPolicySet(ctx, fake, cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf), cli.OutputFormatTable, "n", opts))
		assert.Contains(t, buf.String(), "2h0m0s")
		assert.Equal(t, &secretsclient.RotationPolicy{Enabled: true, Interval: 2 * time.Hour, RetainVersions: 3, RotationLambda: "gen"}, fake.policyReq.Policy)
	})

	t.Run("errors", func(t *testing.T) {
		p := newTestKMSPrinter()
		assert.ErrorIs(t, executeSecretsPolicyGet(ctx, &fakeSecretsClient{}, p, cli.OutputFormatJSON, ""), ErrSecretNameRequired{})
		assert.ErrorIs(t, executeSecretsPolicySet(ctx, &fakeSecretsClient{}, p, cli.OutputFormatJSON, "", secretPolicyOptions{}), ErrSecretNameRequired{})
		requireSecretOperationFailed(t, executeSecretsPolicyGet(ctx, &fakeSecretsClient{err: errFakeSecrets}, p, cli.OutputFormatJSON, "n"), "policy get")
		requireSecretOperationFailed(t, executeSecretsPolicySet(ctx, &fakeSecretsClient{err: errFakeSecrets}, p, cli.OutputFormatJSON, "n", secretPolicyOptions{}), "policy set")
	})
}

func TestParseSecretVersion(t *testing.T) {
	version, err := parseSecretVersion("7")
	require.NoError(t, err)
	assert.Equal(t, 7, version)

	for _, bad := range []string{"0", "-2", "x"} {
		_, err := parseSecretVersion(bad)
		assert.ErrorIs(t, err, ErrInvalidSecretVersion{Value: bad})
	}
}

func TestSecretsCommandTree(t *testing.T) {
	getFlags := func() *cli.CommonFlags { return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON} }
	cmd := NewSecretsCommand(getFlags)

	for _, path := range [][]string{
		{"store"}, {"get"}, {"list"}, {"delete"}, {"rotate"}, {"version"}, {"versions"},
		{"rollback"}, {"status", "enable"}, {"status", "disable"}, {"policy", "get"},
		{"policy", "set"}, {"prefix", "list"}, {"watch"},
	} {
		sub, _, err := cmd.Find(path)
		require.NoError(t, err, path)
		assert.NotNil(t, sub.RunE, path)
	}

	store, _, err := cmd.Find([]string{"store"})
	require.NoError(t, err)
	for _, flag := range []string{"value", "base64", "description", "tag"} {
		assert.NotNil(t, store.Flags().Lookup(flag), flag)
	}
}

func TestSecretsVersionArgRefusedBeforeDial(t *testing.T) {
	cmd := NewSecretsCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	for _, verb := range []string{"version", "rollback"} {
		sub, _, err := cmd.Find([]string{verb})
		require.NoError(t, err)
		assert.ErrorIs(t, sub.RunE(sub, []string{"n", "zero"}), ErrInvalidSecretVersion{Value: "zero"}, verb)
	}
}

func TestSecretsWatchIsSDKGap(t *testing.T) {
	cmd := NewSecretsCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	watch, _, err := cmd.Find([]string{"watch"})
	require.NoError(t, err)
	assert.ErrorIs(t, watch.RunE(watch, []string{"n"}), ErrSecretsSDKGap{Verb: "watch", Method: "SecretsClient.Watch"})
}
