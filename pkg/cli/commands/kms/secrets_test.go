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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

var (
	errSecretsBackend = errors.New("secrets backend unavailable")
	testSecretTime    = time.Unix(1760000000, 0)
	testSecretRaw     = []byte{0x00, 0xff, 's', 'e', 'c'}
)

// fakeSecretsClient implements quicbaassdk.SecretsClient. Each verb records
// its request and returns the configured response or err.
type fakeSecretsClient struct {
	err error

	storeReq     *secrets.StoreSecretRequest
	storeResp    *secrets.StoreSecretResponse
	getPath      string
	getOpts      int
	secret       *secrets.Secret
	listPrefix   string
	listResp     *secrets.ListSecretsResponse
	deletePath   string
	versionReq   *secrets.GetSecretVersionRequest
	versionInfo  *secrets.SecretVersionInfo
	versionsResp *secrets.ListSecretVersionsResponse
	rotateReq    *secrets.RotateSecretRequest
	rotateResp   *secrets.RotateSecretResponse
	rollbackReq  *secrets.RollbackSecretRequest
	rollbackResp *secrets.RollbackSecretResponse
	statusReq    *secrets.UpdateSecretStatusRequest
	policyReq    *secrets.SetRotationPolicyRequest
	policy       *secrets.RotationPolicy
}

func (f *fakeSecretsClient) Store(_ context.Context, req *secrets.StoreSecretRequest) (*secrets.StoreSecretResponse, error) {
	f.storeReq = req
	return f.storeResp, f.err
}

func (f *fakeSecretsClient) Get(_ context.Context, path string, opts ...secrets.GetOption) (*secrets.Secret, error) {
	f.getPath = path
	f.getOpts = len(opts)
	return f.secret, f.err
}

func (f *fakeSecretsClient) List(_ context.Context, prefix string) (*secrets.ListSecretsResponse, error) {
	f.listPrefix = prefix
	return f.listResp, f.err
}

func (f *fakeSecretsClient) Delete(_ context.Context, path string) error {
	f.deletePath = path
	return f.err
}

func (f *fakeSecretsClient) Ensure(_ context.Context, _ *secrets.EnsureSecretRequest) (*secrets.EnsureSecretResponse, error) {
	return nil, f.err
}

func (f *fakeSecretsClient) GetVersion(_ context.Context, req *secrets.GetSecretVersionRequest) (*secrets.SecretVersionInfo, error) {
	f.versionReq = req
	return f.versionInfo, f.err
}

func (f *fakeSecretsClient) ListVersions(_ context.Context, _ string) (*secrets.ListSecretVersionsResponse, error) {
	return f.versionsResp, f.err
}

func (f *fakeSecretsClient) Rotate(_ context.Context, req *secrets.RotateSecretRequest) (*secrets.RotateSecretResponse, error) {
	f.rotateReq = req
	return f.rotateResp, f.err
}

func (f *fakeSecretsClient) Rollback(_ context.Context, req *secrets.RollbackSecretRequest) (*secrets.RollbackSecretResponse, error) {
	f.rollbackReq = req
	return f.rollbackResp, f.err
}

func (f *fakeSecretsClient) UpdateStatus(_ context.Context, req *secrets.UpdateSecretStatusRequest) error {
	f.statusReq = req
	return f.err
}

func (f *fakeSecretsClient) SetRotationPolicy(_ context.Context, req *secrets.SetRotationPolicyRequest) error {
	f.policyReq = req
	return f.err
}

func (f *fakeSecretsClient) GetRotationPolicy(_ context.Context, _ string) (*secrets.RotationPolicy, error) {
	return f.policy, f.err
}

func assertSecretsOperationFailed(t *testing.T, err error, operation string) {
	t.Helper()
	var opErr ErrSecretsOperationFailed
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, operation, opErr.Operation)
	assert.ErrorIs(t, err, errSecretsBackend)
}

func assertSecretsEmptyResponse(t *testing.T, err error, operation string) {
	t.Helper()
	var empty ErrSecretsEmptyResponse
	require.ErrorAs(t, err, &empty)
	assert.Equal(t, operation, empty.Operation)
}

// storedSecretData is the data map `store` writes for testSecretRaw.
func storedSecretData() map[string]interface{} {
	return map[string]interface{}{
		secretValueKey:       base64.StdEncoding.EncodeToString(testSecretRaw),
		secretDescriptionKey: "db password",
	}
}

func TestSetSecretsClientFactory(t *testing.T) {
	t.Run("OverrideAndRestore", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		restore := SetSecretsClientFactory(func(base *cli.BaseCommand) (quicbaassdk.SecretsClient, error) {
			return fake, nil
		})

		client, err := openSecretsClient(nil)
		require.NoError(t, err)
		assert.Same(t, fake, client)

		restore()
		assert.NotNil(t, activeSecretsClientFactory)
	})

	t.Run("FactoryError", func(t *testing.T) {
		restore := SetSecretsClientFactory(func(base *cli.BaseCommand) (quicbaassdk.SecretsClient, error) {
			return nil, errSecretsBackend
		})
		defer restore()

		_, err := openSecretsClient(nil)
		assert.ErrorIs(t, err, errSecretsBackend)
	})
}

func TestSecretValueFlags(t *testing.T) {
	t.Run("PlainValue", func(t *testing.T) {
		raw, err := (&secretValueFlags{value: "hunter2"}).raw()
		require.NoError(t, err)
		assert.Equal(t, []byte("hunter2"), raw)
	})

	t.Run("Base64Value", func(t *testing.T) {
		flags := &secretValueFlags{value: base64.StdEncoding.EncodeToString(testSecretRaw), isBase64: true}
		raw, err := flags.raw()
		require.NoError(t, err)
		assert.Equal(t, testSecretRaw, raw)
	})

	t.Run("MissingValue", func(t *testing.T) {
		_, err := (&secretValueFlags{}).raw()
		assert.ErrorIs(t, err, ErrSecretValueRequired{})
	})

	t.Run("InvalidBase64", func(t *testing.T) {
		_, err := (&secretValueFlags{value: "not base64!", isBase64: true}).raw()
		var invalid ErrSecretValueInvalidBase64
		require.ErrorAs(t, err, &invalid)
		assert.Contains(t, err.Error(), "base64")
		assert.NotNil(t, errors.Unwrap(err))
	})
}

func TestDecodeSecretValue(t *testing.T) {
	t.Run("RoundTripsEncodeSecretData", func(t *testing.T) {
		raw, err := decodeSecretValue("db", encodeSecretData(testSecretRaw, ""))
		require.NoError(t, err)
		assert.Equal(t, testSecretRaw, raw)
	})

	t.Run("MissingValue", func(t *testing.T) {
		_, err := decodeSecretValue("db", map[string]interface{}{"other": "x"})
		var malformed ErrSecretDataMalformed
		require.ErrorAs(t, err, &malformed)
		assert.Equal(t, "db", malformed.Name)
	})

	t.Run("ValueNotBase64", func(t *testing.T) {
		_, err := decodeSecretValue("db", map[string]interface{}{secretValueKey: "%%%"})
		assert.ErrorAs(t, err, &ErrSecretDataMalformed{})
	})

	t.Run("VersionDataNotJSON", func(t *testing.T) {
		_, err := decodeSecretVersionData("db", []byte("raw bytes"))
		assert.ErrorAs(t, err, &ErrSecretDataMalformed{})
	})
}

func TestParseSecretVersion(t *testing.T) {
	version, err := parseSecretVersion("3")
	require.NoError(t, err)
	assert.Equal(t, 3, version)

	for _, bad := range []string{"0", "-1", "two"} {
		_, err := parseSecretVersion(bad)
		assert.ErrorIs(t, err, ErrInvalidSecretVersion{Value: bad}, bad)
	}
}

func TestExecuteSecretsStore(t *testing.T) {
	t.Run("StoresBase64ValueAndDescription", func(t *testing.T) {
		fake := &fakeSecretsClient{storeResp: &secrets.StoreSecretResponse{Version: 1}}
		printer, out := printDEKJSON()

		require.NoError(t, executeSecretsStore(context.Background(), fake, printer, "db", testSecretRaw, "db password"))

		assert.Equal(t, "db", fake.storeReq.Path)
		assert.Equal(t, storedSecretData(), fake.storeReq.Data)
		got := decodeDEKJSON(t, out)
		assert.Equal(t, "db", got["secret_id"])
		assert.Equal(t, float64(1), got["version"])
	})

	t.Run("NoDescriptionKeyWhenEmpty", func(t *testing.T) {
		fake := &fakeSecretsClient{storeResp: &secrets.StoreSecretResponse{Version: 1}}
		printer, _ := printDEKJSON()
		require.NoError(t, executeSecretsStore(context.Background(), fake, printer, "db", testSecretRaw, ""))
		assert.NotContains(t, fake.storeReq.Data, secretDescriptionKey)
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsStore(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "db", testSecretRaw, "")
		assertSecretsOperationFailed(t, err, "store")
		assert.Contains(t, err.Error(), "db")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsStore(context.Background(), &fakeSecretsClient{}, printer, "db", testSecretRaw, "")
		assertSecretsEmptyResponse(t, err, "store")
	})
}

func TestExecuteSecretsGet(t *testing.T) {
	secret := &secrets.Secret{Path: "db", Data: storedSecretData(), Version: 2, CreatedAt: testSecretTime}

	t.Run("PrintsDecodedValue", func(t *testing.T) {
		fake := &fakeSecretsClient{secret: secret}
		printer, out := printDEKJSON()

		require.NoError(t, executeSecretsGet(context.Background(), fake, printer, "db", 0))

		assert.Equal(t, "db", fake.getPath)
		assert.Equal(t, 0, fake.getOpts, "version 0 asks for the current version")
		got := decodeDEKJSON(t, out)
		assert.Equal(t, base64.StdEncoding.EncodeToString(testSecretRaw), got["data"])
		assert.Equal(t, "db password", got["description"])
		assert.Equal(t, float64(2), got["version"])
		assert.Equal(t, float64(testSecretTime.Unix()), got["created_at"])
	})

	t.Run("PassesVersion", func(t *testing.T) {
		fake := &fakeSecretsClient{secret: secret}
		printer, _ := printDEKJSON()
		require.NoError(t, executeSecretsGet(context.Background(), fake, printer, "db", 1))
		assert.Equal(t, 1, fake.getOpts)
	})

	t.Run("MalformedData", func(t *testing.T) {
		fake := &fakeSecretsClient{secret: &secrets.Secret{Data: map[string]interface{}{}}}
		printer, _ := printDEKJSON()
		err := executeSecretsGet(context.Background(), fake, printer, "db", 0)
		assert.ErrorAs(t, err, &ErrSecretDataMalformed{})
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsGet(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "db", 0)
		assertSecretsOperationFailed(t, err, "get")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsGet(context.Background(), &fakeSecretsClient{}, printer, "db", 0)
		assertSecretsEmptyResponse(t, err, "get")
	})
}

func TestExecuteSecretsList(t *testing.T) {
	list := &secrets.ListSecretsResponse{Paths: []string{"db/a", "db/b", "db/c"}}

	t.Run("AppliesLimit", func(t *testing.T) {
		fake := &fakeSecretsClient{listResp: list}
		printer, out := printDEKJSON()

		require.NoError(t, executeSecretsList(context.Background(), fake, printer, "db/", 2))

		assert.Equal(t, "db/", fake.listPrefix)
		got := decodeDEKJSON(t, out)
		assert.Len(t, got["secrets"], 2)
		assert.Equal(t, float64(3), got["total_count"])
		assert.Equal(t, true, got["has_more"])
	})

	t.Run("ZeroLimitListsAll", func(t *testing.T) {
		fake := &fakeSecretsClient{listResp: list}
		printer, out := printDEKJSON()
		require.NoError(t, executeSecretsList(context.Background(), fake, printer, "db/", 0))
		got := decodeDEKJSON(t, out)
		assert.Len(t, got["secrets"], 3)
		assert.Equal(t, false, got["has_more"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsList(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "", 10)
		assertSecretsOperationFailed(t, err, "list")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsList(context.Background(), &fakeSecretsClient{}, printer, "", 10)
		assertSecretsEmptyResponse(t, err, "list")
	})
}

func TestExecuteSecretsDelete(t *testing.T) {
	t.Run("Deletes", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		printer, out := printDEKJSON()
		require.NoError(t, executeSecretsDelete(context.Background(), fake, printer, "db"))
		assert.Equal(t, "db", fake.deletePath)
		assert.Equal(t, true, decodeDEKJSON(t, out)["deleted"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsDelete(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "db")
		assertSecretsOperationFailed(t, err, "delete")
	})
}

func TestExecuteSecretsRotate(t *testing.T) {
	t.Run("SendsDataMapAsJSON", func(t *testing.T) {
		fake := &fakeSecretsClient{rotateResp: &secrets.RotateSecretResponse{SecretID: "db", OldVersion: 1, NewVersion: 2}}
		printer, out := printDEKJSON()

		require.NoError(t, executeSecretsRotate(context.Background(), fake, printer, "db", testSecretRaw))

		assert.Equal(t, "db", fake.rotateReq.SecretID)
		raw, err := decodeSecretVersionData("db", fake.rotateReq.NewData)
		require.NoError(t, err)
		assert.Equal(t, testSecretRaw, raw, "rotated data decodes like stored data")
		got := decodeDEKJSON(t, out)
		assert.Equal(t, float64(1), got["old_version"])
		assert.Equal(t, float64(2), got["new_version"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsRotate(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "db", testSecretRaw)
		assertSecretsOperationFailed(t, err, "rotate")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsRotate(context.Background(), &fakeSecretsClient{}, printer, "db", testSecretRaw)
		assertSecretsEmptyResponse(t, err, "rotate")
	})
}

func TestExecuteSecretsVersion(t *testing.T) {
	data, err := json.Marshal(encodeSecretData(testSecretRaw, ""))
	require.NoError(t, err)
	info := &secrets.SecretVersionInfo{SecretID: "db", Version: 1, Data: data, CreatedAt: testSecretTime, CreatedBy: "admin"}

	t.Run("PrintsDecodedValue", func(t *testing.T) {
		fake := &fakeSecretsClient{versionInfo: info}
		printer, out := printDEKJSON()

		require.NoError(t, executeSecretsVersion(context.Background(), fake, printer, "db", 1))

		assert.Equal(t, secrets.GetSecretVersionRequest{SecretID: "db", Version: 1}, *fake.versionReq)
		got := decodeDEKJSON(t, out)
		assert.Equal(t, base64.StdEncoding.EncodeToString(testSecretRaw), got["data"])
		assert.Equal(t, "admin", got["created_by"])
	})

	t.Run("MalformedData", func(t *testing.T) {
		fake := &fakeSecretsClient{versionInfo: &secrets.SecretVersionInfo{Data: []byte("x")}}
		printer, _ := printDEKJSON()
		err := executeSecretsVersion(context.Background(), fake, printer, "db", 1)
		assert.ErrorAs(t, err, &ErrSecretDataMalformed{})
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsVersion(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "db", 1)
		assertSecretsOperationFailed(t, err, "version")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsVersion(context.Background(), &fakeSecretsClient{}, printer, "db", 1)
		assertSecretsEmptyResponse(t, err, "version")
	})
}

func TestExecuteSecretsVersions(t *testing.T) {
	versions := &secrets.ListSecretVersionsResponse{Versions: []secrets.SecretVersionInfo{
		{Version: 1, CreatedAt: testSecretTime},
		{Version: 2, CreatedAt: testSecretTime, CreatedBy: "admin"},
	}}

	t.Run("AppliesLimit", func(t *testing.T) {
		printer, out := printDEKJSON()
		require.NoError(t, executeSecretsVersions(context.Background(), &fakeSecretsClient{versionsResp: versions}, printer, "db", 1))
		got := decodeDEKJSON(t, out)
		assert.Len(t, got["versions"], 1)
		assert.Equal(t, true, got["has_more"])
	})

	t.Run("ListsAll", func(t *testing.T) {
		printer, out := printDEKJSON()
		require.NoError(t, executeSecretsVersions(context.Background(), &fakeSecretsClient{versionsResp: versions}, printer, "db", 0))
		got := decodeDEKJSON(t, out)
		assert.Len(t, got["versions"], 2)
		assert.Equal(t, false, got["has_more"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsVersions(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "db", 0)
		assertSecretsOperationFailed(t, err, "versions")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsVersions(context.Background(), &fakeSecretsClient{}, printer, "db", 0)
		assertSecretsEmptyResponse(t, err, "versions")
	})
}

func TestExecuteSecretsRollback(t *testing.T) {
	t.Run("RollsBack", func(t *testing.T) {
		fake := &fakeSecretsClient{rollbackResp: &secrets.RollbackSecretResponse{SecretID: "db", NewVersion: 4}}
		printer, out := printDEKJSON()
		require.NoError(t, executeSecretsRollback(context.Background(), fake, printer, "db", 1))
		assert.Equal(t, 1, fake.rollbackReq.TargetVersion)
		assert.Equal(t, float64(4), decodeDEKJSON(t, out)["new_version"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsRollback(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "db", 1)
		assertSecretsOperationFailed(t, err, "rollback")
	})

	t.Run("EmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsRollback(context.Background(), &fakeSecretsClient{}, printer, "db", 1)
		assertSecretsEmptyResponse(t, err, "rollback")
	})
}

func TestExecuteSecretsStatus(t *testing.T) {
	t.Run("PrintsUppercaseStatus", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		printer, out := printDEKJSON()
		require.NoError(t, executeSecretsStatus(context.Background(), fake, printer, "db", secrets.SecretStatusDisabled))
		assert.Equal(t, secrets.SecretStatusDisabled, fake.statusReq.Status)
		assert.Equal(t, "DISABLED", decodeDEKJSON(t, out)["status"])
	})

	t.Run("SDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsStatus(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "db", secrets.SecretStatusEnabled)
		assertSecretsOperationFailed(t, err, "status")
	})
}

func TestExecuteSecretsPolicy(t *testing.T) {
	policy := secrets.RotationPolicy{
		Enabled:        true,
		Interval:       720 * time.Hour,
		NextRotation:   testSecretTime,
		RetainVersions: 5,
		RotationLambda: "random",
	}

	t.Run("GetPrintsPolicy", func(t *testing.T) {
		printer, out := printDEKJSON()
		require.NoError(t, executeSecretsPolicyGet(context.Background(), &fakeSecretsClient{policy: &policy}, printer, "db"))
		got := decodeDEKJSON(t, out)
		assert.Equal(t, float64(720*3600), got["interval_seconds"])
		assert.Equal(t, float64(testSecretTime.Unix()), got["next_rotation"])
		assert.Equal(t, "random", got["method"])
	})

	t.Run("GetSDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsPolicyGet(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "db")
		assertSecretsOperationFailed(t, err, "policy get")
	})

	t.Run("GetEmptyResponse", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsPolicyGet(context.Background(), &fakeSecretsClient{}, printer, "db")
		assertSecretsEmptyResponse(t, err, "policy get")
	})

	t.Run("SetSendsPolicy", func(t *testing.T) {
		fake := &fakeSecretsClient{}
		printer, out := printDEKJSON()
		require.NoError(t, executeSecretsPolicySet(context.Background(), fake, printer, "db", policy))
		assert.Equal(t, "db", fake.policyReq.SecretID)
		assert.Equal(t, policy, *fake.policyReq.Policy)
		assert.Equal(t, float64(5), decodeDEKJSON(t, out)["retain_versions"])
	})

	t.Run("SetSDKError", func(t *testing.T) {
		printer, _ := printDEKJSON()
		err := executeSecretsPolicySet(context.Background(), &fakeSecretsClient{err: errSecretsBackend}, printer, "db", policy)
		assertSecretsOperationFailed(t, err, "policy set")
	})
}

func TestSecretsCommandTree(t *testing.T) {
	cmd := NewSecretsCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })

	names := map[string]bool{}
	for _, sub := range cmd.Commands() {
		names[sub.Name()] = true
	}
	for _, want := range []string{"store", "get", "list", "delete", "rotate", "version", "versions", "rollback", "status", "policy", "prefix"} {
		assert.True(t, names[want], want)
	}
	assert.False(t, names["watch"], "the SDK has no watch verb")
}

func TestSecretsCommandsRejectBadInputBeforeDialing(t *testing.T) {
	// Each case fails in argument or flag validation, so the client factory
	// must never be reached.
	restore := SetSecretsClientFactory(func(base *cli.BaseCommand) (quicbaassdk.SecretsClient, error) {
		t.Fatal("client opened for invalid input")
		return nil, errSecretsBackend
	})
	defer restore()

	cases := []struct {
		name string
		args []string
		want error
	}{
		{"StoreWithoutValue", []string{"store", "db"}, ErrSecretValueRequired{}},
		{"RotateWithoutValue", []string{"rotate", "db"}, ErrSecretValueRequired{}},
		{"StatusWithoutFlag", []string{"status", "db"}, ErrSecretStatusFlagRequired{}},
		{"StatusWithBothFlags", []string{"status", "db", "--enable", "--disable"}, ErrSecretStatusFlagRequired{}},
		{"VersionNotNumber", []string{"version", "db", "x"}, ErrInvalidSecretVersion{Value: "x"}},
		{"RollbackZero", []string{"rollback", "db", "0"}, ErrInvalidSecretVersion{Value: "0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewSecretsCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
			cmd.SetArgs(tc.args)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			assert.ErrorIs(t, cmd.Execute(), tc.want)
		})
	}
}

func TestSecretsCommandFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags { return &cli.CommonFlags{} }

	store := newSecretsStoreCommand(getFlags)
	for _, flag := range []string{"value", "base64", "description"} {
		assert.NotNil(t, store.Flags().Lookup(flag), flag)
	}
	assert.Equal(t, "100", newSecretsListCommand(getFlags).Flags().Lookup("limit").DefValue)
	assert.Nil(t, newSecretsListCommand(getFlags).Flags().Lookup("cursor"), "the SDK list has no cursor")

	set := newSecretsPolicySetCommand(getFlags)
	for _, flag := range []string{"enabled", "interval", "retain-versions", "method"} {
		assert.NotNil(t, set.Flags().Lookup(flag), flag)
	}
}

func TestSecretsErrorMessages(t *testing.T) {
	assert.Contains(t, ErrSecretsOperationFailed{Operation: "list", Err: errSecretsBackend}.Error(), "secrets list failed")
	assert.Contains(t, ErrSecretsOperationFailed{Operation: "get", Name: "db", Err: errSecretsBackend}.Error(), "for db")
	assert.Contains(t, ErrSecretsEmptyResponse{Operation: "get", Name: "db"}.Error(), "no result for db")
	assert.Contains(t, ErrSecretDataMalformed{Name: "db", Reason: "no string value"}.Error(), "no string value")
}
