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

	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// fakeDEKClient implements dekclient.Client; each test sets the calls it expects.
type fakeDEKClient struct {
	createFn       func(*dekclient.CreateDEKRequest) (*dekclient.CreateDEKResponse, error)
	getFn          func(string) (*dekclient.DEKInfo, error)
	listFn         func(*dekclient.ListDEKsRequest) (*dekclient.ListDEKsResponse, error)
	rotateFn       func(*dekclient.RotateDEKRequest) (*dekclient.RotateDEKResponse, error)
	deleteFn       func(*dekclient.DeleteDEKRequest) (*dekclient.DeleteDEKResponse, error)
	statusFn       func(string) (*dekclient.DEKStatusResponse, error)
	setDefaultFn   func(string) (*dekclient.SetDefaultDEKResponse, error)
	setSafetyFn    func(*dekclient.SetDEKSafetyRequest) error
	clearSafetyFn  func(string) error
	clearSafetyHit bool
}

var errFakeDEKUnset = errors.New("fake DEK call not set")

func (f *fakeDEKClient) CreateDEK(_ context.Context, req *dekclient.CreateDEKRequest) (*dekclient.CreateDEKResponse, error) {
	if f.createFn == nil {
		return nil, errFakeDEKUnset
	}
	return f.createFn(req)
}

func (f *fakeDEKClient) GetDEK(_ context.Context, path string) (*dekclient.DEKInfo, error) {
	if f.getFn == nil {
		return nil, errFakeDEKUnset
	}
	return f.getFn(path)
}

func (f *fakeDEKClient) ListDEKs(_ context.Context, req *dekclient.ListDEKsRequest) (*dekclient.ListDEKsResponse, error) {
	if f.listFn == nil {
		return nil, errFakeDEKUnset
	}
	return f.listFn(req)
}

func (f *fakeDEKClient) RotateDEK(_ context.Context, req *dekclient.RotateDEKRequest) (*dekclient.RotateDEKResponse, error) {
	if f.rotateFn == nil {
		return nil, errFakeDEKUnset
	}
	return f.rotateFn(req)
}

func (f *fakeDEKClient) DeleteDEK(_ context.Context, req *dekclient.DeleteDEKRequest) (*dekclient.DeleteDEKResponse, error) {
	if f.deleteFn == nil {
		return nil, errFakeDEKUnset
	}
	return f.deleteFn(req)
}

func (f *fakeDEKClient) GetDEKStatus(_ context.Context, path string) (*dekclient.DEKStatusResponse, error) {
	if f.statusFn == nil {
		return nil, errFakeDEKUnset
	}
	return f.statusFn(path)
}

func (f *fakeDEKClient) SetDefaultDEK(_ context.Context, path string) (*dekclient.SetDefaultDEKResponse, error) {
	if f.setDefaultFn == nil {
		return nil, errFakeDEKUnset
	}
	return f.setDefaultFn(path)
}

func (f *fakeDEKClient) SetDEKSafety(_ context.Context, req *dekclient.SetDEKSafetyRequest) error {
	if f.setSafetyFn == nil {
		return errFakeDEKUnset
	}
	return f.setSafetyFn(req)
}

func (f *fakeDEKClient) ClearDEKSafety(_ context.Context, path string) error {
	f.clearSafetyHit = true
	if f.clearSafetyFn == nil {
		return errFakeDEKUnset
	}
	return f.clearSafetyFn(path)
}

func (f *fakeDEKClient) StartReencryption(context.Context, *dekclient.StartReencryptionRequest) (*dekclient.StartReencryptionResponse, error) {
	return nil, errFakeDEKUnset
}

func (f *fakeDEKClient) GetReencryptionProgress(context.Context, *dekclient.GetReencryptionProgressRequest) (*dekclient.ReencryptionProgressResponse, error) {
	return nil, errFakeDEKUnset
}

// newDEKJSONPrinter returns a JSON printer and the buffer it writes to.
func newDEKJSONPrinter() (*cli.Printer, *bytes.Buffer) {
	var buf bytes.Buffer
	return cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &buf), &buf
}

var dekTestCreatedAt = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func testDEKInfo(path string) *dekclient.DEKInfo {
	return &dekclient.DEKInfo{
		Path:           path,
		Algorithm:      "AES-256-GCM",
		Version:        1,
		Status:         "active",
		CreatedAt:      dekTestCreatedAt,
		MaxUsageCount:  1000,
		WarningPercent: 80,
		Description:    "orders",
	}
}

func TestExecuteDEKCreate(t *testing.T) {
	t.Run("SendsPathAndAES256GCM", func(t *testing.T) {
		var got *dekclient.CreateDEKRequest
		fake := &fakeDEKClient{createFn: func(req *dekclient.CreateDEKRequest) (*dekclient.CreateDEKResponse, error) {
			got = req
			return &dekclient.CreateDEKResponse{DEK: testDEKInfo(req.Path)}, nil
		}}
		printer, buf := newDEKJSONPrinter()

		require.NoError(t, executeDEKCreate(context.Background(), fake, printer, "/t/app"))
		assert.Equal(t, &dekclient.CreateDEKRequest{Path: "/t/app", Algorithm: "AES-256-GCM"}, got)

		var out dekOutput
		require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
		assert.Equal(t, "/t/app", out.Path)
		assert.Equal(t, 1, out.Version)
		assert.Equal(t, "2026-10-21T12:00:00Z", out.CreatedAt)
		assert.Empty(t, out.RotatedAt, "a zero rotated_at is omitted, not printed as year 1")
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("exists")
		fake := &fakeDEKClient{createFn: func(*dekclient.CreateDEKRequest) (*dekclient.CreateDEKResponse, error) {
			return nil, sdkErr
		}}
		err := executeDEKCreate(context.Background(), fake, newTestKMSPrinter(), "/t/app")
		assert.ErrorIs(t, err, sdkErr)
		assert.Equal(t, ErrDEKOperationFailed{Verb: "create", Path: "/t/app", Err: sdkErr}, err)
	})
}

func TestExecuteDEKGet(t *testing.T) {
	t.Run("PrintsDEK", func(t *testing.T) {
		fake := &fakeDEKClient{getFn: func(path string) (*dekclient.DEKInfo, error) {
			return testDEKInfo(path), nil
		}}
		printer, buf := newDEKJSONPrinter()

		require.NoError(t, executeDEKGet(context.Background(), fake, printer, "/t/app"))
		var out dekOutput
		require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
		assert.Equal(t, "orders", out.Description)
		assert.Equal(t, uint64(1000), out.MaxUsageCount)
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("not found")
		fake := &fakeDEKClient{getFn: func(string) (*dekclient.DEKInfo, error) { return nil, sdkErr }}
		err := executeDEKGet(context.Background(), fake, newTestKMSPrinter(), "/t/missing")
		assert.ErrorIs(t, err, sdkErr)
	})
}

func TestExecuteDEKList(t *testing.T) {
	t.Run("MapsFlagsAndPrintsEveryDEK", func(t *testing.T) {
		var got *dekclient.ListDEKsRequest
		fake := &fakeDEKClient{listFn: func(req *dekclient.ListDEKsRequest) (*dekclient.ListDEKsResponse, error) {
			got = req
			return &dekclient.ListDEKsResponse{
				DEKs:       []dekclient.DEKInfo{*testDEKInfo("/t/a"), *testDEKInfo("/t/b")},
				TotalCount: 2,
			}, nil
		}}
		printer, buf := newDEKJSONPrinter()

		opts := dekListOptions{Prefix: "/t", Recursive: true, Limit: 5}
		require.NoError(t, executeDEKList(context.Background(), fake, printer, opts))
		assert.Equal(t, &dekclient.ListDEKsRequest{Prefix: "/t", Recursive: true, Limit: 5}, got)

		var out dekListOutput
		require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
		require.Len(t, out.DEKs, 2)
		assert.Equal(t, "/t/b", out.DEKs[1].Path)
		assert.Equal(t, 2, out.TotalCount)
	})

	t.Run("CursorIsAnSDKGap", func(t *testing.T) {
		fake := &fakeDEKClient{}
		err := executeDEKList(context.Background(), fake, newTestKMSPrinter(), dekListOptions{Limit: 5, Cursor: "c1"})
		var gap ErrDEKSDKGap
		require.ErrorAs(t, err, &gap)
		assert.Contains(t, gap.Missing, "ListDEKsRequest.Cursor")
	})

	t.Run("NonPositiveLimit", func(t *testing.T) {
		err := executeDEKList(context.Background(), &fakeDEKClient{}, newTestKMSPrinter(), dekListOptions{Limit: 0})
		assert.Equal(t, ErrInvalidDEKLimit{Limit: 0}, err)
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("unavailable")
		fake := &fakeDEKClient{listFn: func(*dekclient.ListDEKsRequest) (*dekclient.ListDEKsResponse, error) {
			return nil, sdkErr
		}}
		err := executeDEKList(context.Background(), fake, newTestKMSPrinter(), dekListOptions{Limit: 5})
		assert.ErrorIs(t, err, sdkErr)
	})
}

func TestExecuteDEKDelete(t *testing.T) {
	t.Run("SendsForce", func(t *testing.T) {
		var got *dekclient.DeleteDEKRequest
		fake := &fakeDEKClient{deleteFn: func(req *dekclient.DeleteDEKRequest) (*dekclient.DeleteDEKResponse, error) {
			got = req
			return &dekclient.DeleteDEKResponse{Path: req.Path, Deleted: true}, nil
		}}
		printer, buf := newDEKJSONPrinter()

		require.NoError(t, executeDEKDelete(context.Background(), fake, printer, "/t/app", true))
		assert.Equal(t, &dekclient.DeleteDEKRequest{Path: "/t/app", Force: true}, got)
		assert.JSONEq(t, `{"path":"/t/app","deleted":true}`, buf.String())
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("protected")
		fake := &fakeDEKClient{deleteFn: func(*dekclient.DeleteDEKRequest) (*dekclient.DeleteDEKResponse, error) {
			return nil, sdkErr
		}}
		err := executeDEKDelete(context.Background(), fake, newTestKMSPrinter(), "/t/app", false)
		assert.ErrorIs(t, err, sdkErr)
	})
}

func TestExecuteDEKRotate(t *testing.T) {
	t.Run("PrintsVersions", func(t *testing.T) {
		var got *dekclient.RotateDEKRequest
		fake := &fakeDEKClient{rotateFn: func(req *dekclient.RotateDEKRequest) (*dekclient.RotateDEKResponse, error) {
			got = req
			return &dekclient.RotateDEKResponse{Path: req.Path, OldVersion: 1, NewVersion: 2}, nil
		}}
		printer, buf := newDEKJSONPrinter()

		require.NoError(t, executeDEKRotate(context.Background(), fake, printer, "/t/app"))
		assert.Equal(t, &dekclient.RotateDEKRequest{Path: "/t/app"}, got)
		assert.JSONEq(t, `{"path":"/t/app","old_version":1,"new_version":2}`, buf.String())
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("not found")
		fake := &fakeDEKClient{rotateFn: func(*dekclient.RotateDEKRequest) (*dekclient.RotateDEKResponse, error) {
			return nil, sdkErr
		}}
		err := executeDEKRotate(context.Background(), fake, newTestKMSPrinter(), "/t/app")
		assert.ErrorIs(t, err, sdkErr)
	})
}

func TestExecuteDEKStatus(t *testing.T) {
	t.Run("PrintsDEKAndReencryption", func(t *testing.T) {
		fake := &fakeDEKClient{statusFn: func(path string) (*dekclient.DEKStatusResponse, error) {
			return &dekclient.DEKStatusResponse{
				DEK: testDEKInfo(path),
				ReencryptionProgress: &dekclient.ReencryptionProgress{
					InProgress: true, TotalKeys: 10, ProcessedKeys: 4, StartedAt: dekTestCreatedAt,
				},
			}, nil
		}}
		printer, buf := newDEKJSONPrinter()

		require.NoError(t, executeDEKStatus(context.Background(), fake, printer, "/t/app"))
		var out dekStatusOutput
		require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
		assert.Equal(t, "/t/app", out.Path)
		assert.Equal(t, 80, out.WarningPercent)
		require.NotNil(t, out.Reencryption)
		assert.Equal(t, 4, out.Reencryption.ProcessedKeys)
		assert.Equal(t, "2026-10-21T12:00:00Z", out.Reencryption.StartedAt)
	})

	t.Run("NoReencryptionOmitsTheObject", func(t *testing.T) {
		fake := &fakeDEKClient{statusFn: func(path string) (*dekclient.DEKStatusResponse, error) {
			return &dekclient.DEKStatusResponse{DEK: testDEKInfo(path)}, nil
		}}
		printer, buf := newDEKJSONPrinter()

		require.NoError(t, executeDEKStatus(context.Background(), fake, printer, "/t/app"))
		assert.NotContains(t, buf.String(), "reencryption")
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("not found")
		fake := &fakeDEKClient{statusFn: func(string) (*dekclient.DEKStatusResponse, error) { return nil, sdkErr }}
		err := executeDEKStatus(context.Background(), fake, newTestKMSPrinter(), "/t/app")
		assert.ErrorIs(t, err, sdkErr)
	})
}

func TestExecuteDEKSetDefault(t *testing.T) {
	t.Run("PrintsPreviousDefault", func(t *testing.T) {
		fake := &fakeDEKClient{setDefaultFn: func(path string) (*dekclient.SetDefaultDEKResponse, error) {
			return &dekclient.SetDefaultDEKResponse{Path: path, PreviousDefault: "/t/old"}, nil
		}}
		printer, buf := newDEKJSONPrinter()

		require.NoError(t, executeDEKSetDefault(context.Background(), fake, printer, "/t/app"))
		assert.JSONEq(t, `{"path":"/t/app","previous_default":"/t/old"}`, buf.String())
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("not found")
		fake := &fakeDEKClient{setDefaultFn: func(string) (*dekclient.SetDefaultDEKResponse, error) { return nil, sdkErr }}
		err := executeDEKSetDefault(context.Background(), fake, newTestKMSPrinter(), "/t/app")
		assert.ErrorIs(t, err, sdkErr)
	})
}

func TestExecuteDEKSetSafety(t *testing.T) {
	t.Run("SendsLimits", func(t *testing.T) {
		var got *dekclient.SetDEKSafetyRequest
		fake := &fakeDEKClient{setSafetyFn: func(req *dekclient.SetDEKSafetyRequest) error {
			got = req
			return nil
		}}
		opts := dekSafetyOptions{MaxOperations: 1000, MaxBytes: 4096, WarningPercent: 75}

		require.NoError(t, executeDEKSetSafety(context.Background(), fake, newTestKMSPrinter(), "/t/app", opts))
		assert.Equal(t, &dekclient.SetDEKSafetyRequest{Path: "/t/app", MaxOperations: 1000, MaxBytes: 4096, WarningPercent: 75}, got)
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("invalid limits")
		fake := &fakeDEKClient{setSafetyFn: func(*dekclient.SetDEKSafetyRequest) error { return sdkErr }}
		err := executeDEKSetSafety(context.Background(), fake, newTestKMSPrinter(), "/t/app", dekSafetyOptions{})
		assert.ErrorIs(t, err, sdkErr)
	})
}

func TestExecuteDEKClearSafety(t *testing.T) {
	t.Run("ClearsWithForce", func(t *testing.T) {
		var got string
		fake := &fakeDEKClient{clearSafetyFn: func(path string) error {
			got = path
			return nil
		}}
		require.NoError(t, executeDEKClearSafety(context.Background(), fake, newTestKMSPrinter(), "/t/app", true))
		assert.Equal(t, "/t/app", got)
	})

	t.Run("RefusesWithoutForce", func(t *testing.T) {
		fake := &fakeDEKClient{}
		err := executeDEKClearSafety(context.Background(), fake, newTestKMSPrinter(), "/t/app", false)
		assert.Equal(t, ErrDEKClearSafetyNotConfirmed{Path: "/t/app"}, err)
		assert.False(t, fake.clearSafetyHit, "the SDK must not be called without --force")
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("not found")
		fake := &fakeDEKClient{clearSafetyFn: func(string) error { return sdkErr }}
		err := executeDEKClearSafety(context.Background(), fake, newTestKMSPrinter(), "/t/app", true)
		assert.ErrorIs(t, err, sdkErr)
	})
}

func TestSetDEKClientFactory(t *testing.T) {
	t.Run("OverrideAndRestore", func(t *testing.T) {
		fake := &fakeDEKClient{}
		restore := setDEKClientFactory(func(*cli.BaseCommand) (dekclient.Client, error) { return fake, nil })

		client, err := activeDEKClientFactory(nil)
		require.NoError(t, err)
		assert.Same(t, fake, client)

		restore()
		assert.NotNil(t, activeDEKClientFactory)
	})

	t.Run("FactoryError", func(t *testing.T) {
		factoryErr := errors.New("no daemon")
		restore := setDEKClientFactory(func(*cli.BaseCommand) (dekclient.Client, error) { return nil, factoryErr })
		defer restore()

		_, err := activeDEKClientFactory(nil)
		assert.ErrorIs(t, err, factoryErr)
	})
}

// TestDEKCommands_ParseDocumentedArguments runs every verb with the documented
// arguments and flags. With no CLI context set, each one parses and then stops
// at the connection, so an unknown flag or wrong arity fails here instead.
func TestDEKCommands_ParseDocumentedArguments(t *testing.T) {
	tests := map[string][]string{
		"create":       {"create", "/t/app"},
		"get":          {"get", "/t/app"},
		"list":         {"list", "--prefix", "/t", "--recursive", "--limit", "5"},
		"delete":       {"delete", "/t/app", "--force"},
		"rotate":       {"rotate", "/t/app"},
		"status":       {"status", "/t/app"},
		"set-default":  {"set-default", "/t/app"},
		"set-safety":   {"set-safety", "/t/app", "--max-operations", "10", "--max-bytes", "20", "--warn-percent", "70"},
		"clear-safety": {"clear-safety", "/t/app", "--force"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := NewDEKCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
			cmd.SetArgs(args)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			assert.ErrorIs(t, cmd.Execute(), cli.ErrNoContextSet{})
		})
	}
}

func TestDEKCommands_RejectUndocumentedInput(t *testing.T) {
	tests := map[string][]string{
		"create --algorithm":     {"create", "/t/app", "--algorithm", "AES-256-GCM"},
		"create without path":    {"create"},
		"set-default version":    {"set-default", "/t/app", "2"},
		"rotate --background":    {"rotate", "/t/app", "--background"},
		"delete --migrate-to":    {"delete", "/t/app", "--migrate-to", "/t/b"},
		"create --description":   {"create", "/t/app", "--description", "x"},
		"list positional prefix": {"list", "/t"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := NewDEKCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
			cmd.SetArgs(args)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			err := cmd.Execute()
			require.Error(t, err)
			assert.NotErrorIs(t, err, cli.ErrNoContextSet{}, "undocumented input must fail at parse, before connecting")
		})
	}
}
