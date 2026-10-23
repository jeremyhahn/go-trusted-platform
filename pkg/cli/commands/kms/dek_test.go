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
	"google.golang.org/grpc"

	kmspb "github.com/jeremyhahn/go-quicbaas/api/proto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	sdkkms "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
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

		require.NoError(t, executeDEKCreate(context.Background(), fake, printer, "/t/app", dekSafetyOptions{}))
		assert.Equal(t, &dekclient.CreateDEKRequest{Path: "/t/app", Algorithm: "AES-256-GCM"}, got)

		var out dekOutput
		require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
		assert.Equal(t, "/t/app", out.Path)
		assert.Equal(t, 1, out.Version)
		assert.Equal(t, "2026-10-21T12:00:00Z", out.CreatedAt)
		assert.Empty(t, out.RotatedAt, "a zero rotated_at is omitted, not printed as year 1")
	})

	t.Run("SendsLimits", func(t *testing.T) {
		var got *dekclient.CreateDEKRequest
		fake := &fakeDEKClient{createFn: func(req *dekclient.CreateDEKRequest) (*dekclient.CreateDEKResponse, error) {
			got = req
			return &dekclient.CreateDEKResponse{DEK: testDEKInfo(req.Path)}, nil
		}}
		limits := dekSafetyOptions{MaxOperations: 1000, MaxBytes: 4096, WarningPercent: 75}

		require.NoError(t, executeDEKCreate(context.Background(), fake, newTestKMSPrinter(), "/t/app", limits))
		assert.Equal(t, &dekclient.CreateDEKRequest{
			Path: "/t/app", Algorithm: "AES-256-GCM", MaxOperations: 1000, MaxBytes: 4096, WarningPercent: 75,
		}, got, "the limits travel on CreateDEK, which every SDK transport serves")
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("exists")
		fake := &fakeDEKClient{createFn: func(*dekclient.CreateDEKRequest) (*dekclient.CreateDEKResponse, error) {
			return nil, sdkErr
		}}
		err := executeDEKCreate(context.Background(), fake, newTestKMSPrinter(), "/t/app", dekSafetyOptions{})
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
	t.Run("PrintsTheSourcesStatus", func(t *testing.T) {
		source := func(_ context.Context, path string) (dekStatusOutput, error) {
			return dekStatusOutput{dekOutput: dekOutput{Path: path, WarningPercent: 80}}, nil
		}
		printer, buf := newDEKJSONPrinter()

		require.NoError(t, executeDEKStatus(context.Background(), source, printer, "/t/app"))
		var out dekStatusOutput
		require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
		assert.Equal(t, "/t/app", out.Path)
		assert.Equal(t, 80, out.WarningPercent)
	})

	t.Run("SourceErrorIsAStatusFailure", func(t *testing.T) {
		svcErr := errors.New("not found")
		source := func(context.Context, string) (dekStatusOutput, error) { return dekStatusOutput{}, svcErr }
		err := executeDEKStatus(context.Background(), source, newTestKMSPrinter(), "/t/app")
		assert.ErrorIs(t, err, svcErr)
		var opErr ErrDEKOperationFailed
		require.ErrorAs(t, err, &opErr)
		assert.Equal(t, "status", opErr.Verb)
	})
}

func TestPlatformDEKStatus(t *testing.T) {
	t.Run("MapsDEKAndReencryption", func(t *testing.T) {
		fake := &fakeDEKStatusClient{resp: &kmspb.GetDEKStatusResponse{
			Dek: &kmspb.DEKMetadata{
				Path:           "/t/app",
				Algorithm:      kmspb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
				Version:        2,
				Status:         "active",
				CreatedAt:      dekTestCreatedAt.Unix(),
				WarningPercent: 80,
			},
			ReencryptionProgress: &kmspb.ReencryptionProgress{
				InProgress: true, TotalKeys: 10, ProcessedKeys: 4, StartedAt: dekTestCreatedAt.Unix(),
			},
		}}

		out, err := platformDEKStatus(fake)(context.Background(), "/t/app")
		require.NoError(t, err)
		assert.Equal(t, "/t/app", fake.lastPath)
		assert.Equal(t, "/t/app", out.Path)
		assert.Equal(t, dekCreateAlgorithm, out.Algorithm)
		assert.Equal(t, 2, out.Version)
		assert.Equal(t, 80, out.WarningPercent)
		assert.Equal(t, "2026-10-21T12:00:00Z", out.CreatedAt)
		assert.Empty(t, out.RotatedAt)
		require.NotNil(t, out.Reencryption)
		assert.Equal(t, 4, out.Reencryption.ProcessedKeys)
		assert.InDelta(t, 40.0, out.Reencryption.PercentComplete, 1e-9)
		assert.Equal(t, "2026-10-21T12:00:00Z", out.Reencryption.StartedAt)
	})

	t.Run("NoReencryptionLeavesItNil", func(t *testing.T) {
		fake := &fakeDEKStatusClient{resp: &kmspb.GetDEKStatusResponse{Dek: &kmspb.DEKMetadata{Path: "/t/app"}}}
		out, err := platformDEKStatus(fake)(context.Background(), "/t/app")
		require.NoError(t, err)
		assert.Nil(t, out.Reencryption)
	})

	t.Run("NoDEKMetadataIsRefused", func(t *testing.T) {
		fake := &fakeDEKStatusClient{resp: &kmspb.GetDEKStatusResponse{}}
		_, err := platformDEKStatus(fake)(context.Background(), "/t/app")
		assert.ErrorIs(t, err, ErrDEKStatusEmpty{Path: "/t/app"})
	})

	t.Run("ServiceError", func(t *testing.T) {
		svcErr := errors.New("unavailable")
		_, err := platformDEKStatus(&fakeDEKStatusClient{err: svcErr})(context.Background(), "/t/app")
		assert.ErrorIs(t, err, svcErr)
	})
}

func TestSDKDEKStatus(t *testing.T) {
	t.Run("MapsDEKAndReencryption", func(t *testing.T) {
		fake := &fakeDEKClient{statusFn: func(path string) (*dekclient.DEKStatusResponse, error) {
			return &dekclient.DEKStatusResponse{
				DEK: testDEKInfo(path),
				ReencryptionProgress: &dekclient.ReencryptionProgress{
					InProgress: true, TotalKeys: 10, ProcessedKeys: 4, StartedAt: dekTestCreatedAt,
				},
			}, nil
		}}

		out, err := sdkDEKStatus(fake)(context.Background(), "/t/app")
		require.NoError(t, err)
		assert.Equal(t, "/t/app", out.Path)
		assert.Equal(t, 80, out.WarningPercent)
		require.NotNil(t, out.Reencryption)
		assert.Equal(t, 4, out.Reencryption.ProcessedKeys)
		assert.Equal(t, "2026-10-21T12:00:00Z", out.Reencryption.StartedAt)
	})

	t.Run("NoDEKIsRefused", func(t *testing.T) {
		fake := &fakeDEKClient{statusFn: func(string) (*dekclient.DEKStatusResponse, error) {
			return &dekclient.DEKStatusResponse{}, nil
		}}
		_, err := sdkDEKStatus(fake)(context.Background(), "/t/app")
		assert.ErrorIs(t, err, ErrDEKStatusEmpty{Path: "/t/app"})
	})

	t.Run("SDKError", func(t *testing.T) {
		sdkErr := errors.New("not found")
		fake := &fakeDEKClient{statusFn: func(string) (*dekclient.DEKStatusResponse, error) { return nil, sdkErr }}
		_, err := sdkDEKStatus(fake)(context.Background(), "/t/app")
		assert.ErrorIs(t, err, sdkErr)
	})
}

// fakeStatusPlatformClient is a platform.Client with only the transport and
// the DEKManagement client dekStatusSourceFor reads.
type fakeStatusPlatformClient struct {
	platform.Client
	protocol platform.Protocol
	dek      kmspb.DEKManagementClient
}

func (f fakeStatusPlatformClient) Protocol() platform.Protocol    { return f.protocol }
func (f fakeStatusPlatformClient) DEK() kmspb.DEKManagementClient { return f.dek }

// fakeDEKManagementClient answers GetDEKStatus for dekStatusSourceFor tests.
type fakeDEKManagementClient struct {
	kmspb.DEKManagementClient
	fakeDEKStatusClient
}

func (f *fakeDEKManagementClient) GetDEKStatus(ctx context.Context, in *kmspb.GetDEKStatusRequest, opts ...grpc.CallOption) (*kmspb.GetDEKStatusResponse, error) {
	return f.fakeDEKStatusClient.GetDEKStatus(ctx, in, opts...)
}

func TestDEKStatusSourceFor(t *testing.T) {
	noSDK := func() (dekclient.Client, error) {
		t.Fatal("the SDK DEK client must not be opened on a transport that carries DEKManagement")
		return nil, nil
	}

	for _, protocol := range []platform.Protocol{platform.ProtocolGRPC, platform.ProtocolUnix, platform.ProtocolQUIC} {
		t.Run("PlatformServiceOver"+protocol.String(), func(t *testing.T) {
			dek := &fakeDEKManagementClient{fakeDEKStatusClient: fakeDEKStatusClient{
				resp: &kmspb.GetDEKStatusResponse{Dek: &kmspb.DEKMetadata{Path: "/t/app"}},
			}}
			source, err := dekStatusSourceFor(fakeStatusPlatformClient{protocol: protocol, dek: dek}, noSDK)
			require.NoError(t, err)

			out, err := source(context.Background(), "/t/app")
			require.NoError(t, err)
			assert.Equal(t, "/t/app", out.Path)
			assert.Equal(t, "/t/app", dek.lastPath)
		})
	}

	t.Run("NoPlatformConnectionIsUnavailable", func(t *testing.T) {
		_, err := dekStatusSourceFor(fakeStatusPlatformClient{protocol: platform.ProtocolUnix}, noSDK)
		assert.ErrorIs(t, err, ErrDEKServiceUnavailable{})
	})

	t.Run("OtherTransportsKeepTheSDKClient", func(t *testing.T) {
		sdk := &fakeDEKClient{statusFn: func(path string) (*dekclient.DEKStatusResponse, error) {
			return &dekclient.DEKStatusResponse{DEK: testDEKInfo(path)}, nil
		}}
		source, err := dekStatusSourceFor(fakeStatusPlatformClient{protocol: platform.ProtocolREST},
			func() (dekclient.Client, error) { return sdk, nil })
		require.NoError(t, err)

		out, err := source(context.Background(), "/t/app")
		require.NoError(t, err)
		assert.Equal(t, "/t/app", out.Path)
	})

	t.Run("SDKClientErrorStopsTheCommand", func(t *testing.T) {
		sdkErr := errors.New("quicbaas not configured")
		_, err := dekStatusSourceFor(fakeStatusPlatformClient{protocol: platform.ProtocolMCP},
			func() (dekclient.Client, error) { return nil, sdkErr })
		assert.ErrorIs(t, err, sdkErr)
	})
}

// fakeDEKStatusClient records the status request and answers resp or err.
type fakeDEKStatusClient struct {
	resp     *kmspb.GetDEKStatusResponse
	err      error
	lastPath string
}

func (f *fakeDEKStatusClient) GetDEKStatus(_ context.Context, in *kmspb.GetDEKStatusRequest, _ ...grpc.CallOption) (*kmspb.GetDEKStatusResponse, error) {
	f.lastPath = in.GetPath()
	return f.resp, f.err
}

func TestDEKAlgorithmName(t *testing.T) {
	t.Run("KnownAlgorithmsUseTheSDKNames", func(t *testing.T) {
		assert.Equal(t, sdkkms.AlgorithmAES256GCM.String(), dekAlgorithmName(kmspb.KeyAlgorithm_KEY_ALG_AES_256_GCM))
		assert.Equal(t, sdkkms.AlgorithmChaCha20Poly1305.String(), dekAlgorithmName(kmspb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305))
	})

	t.Run("UnmappedAlgorithmPrintsItsEnumName", func(t *testing.T) {
		assert.Equal(t, kmspb.KeyAlgorithm(9999).String(), dekAlgorithmName(kmspb.KeyAlgorithm(9999)))
	})
}

func TestNewDEKOutputFromPb(t *testing.T) {
	t.Run("NilMetadataIsEmpty", func(t *testing.T) {
		assert.Equal(t, dekOutput{}, newDEKOutputFromPb(nil))
	})

	t.Run("CopiesEveryField", func(t *testing.T) {
		out := newDEKOutputFromPb(&kmspb.DEKMetadata{
			Path: "/t/app", Status: "active", IsDefault: true, RotatedAt: dekTestCreatedAt.Unix(),
			UsageCount: 3, BytesUsed: 4, MaxUsageCount: 5, MaxBytesUsed: 6,
			Description: "d", BackendType: "software",
		})
		assert.Equal(t, dekOutput{
			Path: "/t/app", Algorithm: kmspb.KeyAlgorithm(0).String(), Status: "active", IsDefault: true,
			RotatedAt: "2026-10-21T12:00:00Z", UsageCount: 3, BytesUsed: 4, MaxUsageCount: 5, MaxBytesUsed: 6,
			Description: "d", BackendType: "software",
		}, out)
	})
}

func TestReencryptionPercent(t *testing.T) {
	assert.InDelta(t, 25.0, reencryptionPercent(1, 4), 1e-9)
	assert.Zero(t, reencryptionPercent(3, 0), "no keys is zero, not a division by zero")
	assert.Zero(t, reencryptionPercent(3, -1), "a negative total is zero")
}

func TestSetDEKStatusSourceFactory(t *testing.T) {
	t.Run("OverrideAndRestore", func(t *testing.T) {
		called := false
		restore := setDEKStatusSourceFactory(func(*cli.BaseCommand) (dekStatusSource, error) {
			called = true
			return func(context.Context, string) (dekStatusOutput, error) { return dekStatusOutput{}, nil }, nil
		})

		source, err := activeDEKStatusSourceFactory(nil)
		require.NoError(t, err)
		assert.NotNil(t, source)
		assert.True(t, called)

		restore()
		assert.NotNil(t, activeDEKStatusSourceFactory)
	})

	t.Run("FactoryErrorStopsTheCommand", func(t *testing.T) {
		factoryErr := errors.New("no daemon")
		restore := setDEKStatusSourceFactory(func(*cli.BaseCommand) (dekStatusSource, error) { return nil, factoryErr })
		defer restore()

		_, err := activeDEKStatusSourceFactory(nil)
		assert.ErrorIs(t, err, factoryErr)
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

// fakeDEKSafetyRPC records the default and safety calls platformDEKSafety makes
// on platformd's DEKManagement service and answers them, or fails with err.
type fakeDEKSafetyRPC struct {
	kmspb.DEKManagementClient
	err         error
	lastDefault *kmspb.SetDefaultDEKRequest
	lastSafety  *kmspb.SetDEKSafetyRequest
	lastClear   *kmspb.ClearDEKSafetyRequest
}

func (f *fakeDEKSafetyRPC) SetDefaultDEK(_ context.Context, in *kmspb.SetDefaultDEKRequest, _ ...grpc.CallOption) (*kmspb.SetDefaultDEKResponse, error) {
	f.lastDefault = in
	if f.err != nil {
		return nil, f.err
	}
	return &kmspb.SetDefaultDEKResponse{Path: in.GetPath(), PreviousDefault: "/t/old"}, nil
}

func (f *fakeDEKSafetyRPC) SetDEKSafety(_ context.Context, in *kmspb.SetDEKSafetyRequest, _ ...grpc.CallOption) (*kmspb.SetDEKSafetyResponse, error) {
	f.lastSafety = in
	if f.err != nil {
		return nil, f.err
	}
	return &kmspb.SetDEKSafetyResponse{Path: in.GetPath()}, nil
}

func (f *fakeDEKSafetyRPC) ClearDEKSafety(_ context.Context, in *kmspb.ClearDEKSafetyRequest, _ ...grpc.CallOption) (*kmspb.ClearDEKSafetyResponse, error) {
	f.lastClear = in
	if f.err != nil {
		return nil, f.err
	}
	return &kmspb.ClearDEKSafetyResponse{Path: in.GetPath()}, nil
}

func TestPlatformDEKSafety(t *testing.T) {
	ctx := context.Background()

	t.Run("SendsEachCallToDEKManagement", func(t *testing.T) {
		rpc := &fakeDEKSafetyRPC{}
		client := platformDEKSafety{client: rpc}

		def, err := client.SetDefaultDEK(ctx, "/t/app")
		require.NoError(t, err)
		assert.Equal(t, "/t/app", rpc.lastDefault.GetPath())
		assert.Equal(t, &dekclient.SetDefaultDEKResponse{Path: "/t/app", PreviousDefault: "/t/old"}, def)

		require.NoError(t, client.SetDEKSafety(ctx, &dekclient.SetDEKSafetyRequest{
			Path: "/t/app", MaxOperations: 1000, MaxBytes: 4096, WarningPercent: 75,
		}))
		assert.Equal(t, "/t/app", rpc.lastSafety.GetPath())
		assert.Equal(t, uint64(1000), rpc.lastSafety.GetMaxOperations())
		assert.Equal(t, uint64(4096), rpc.lastSafety.GetMaxBytes())
		assert.Equal(t, int32(75), rpc.lastSafety.GetWarningPercent())

		require.NoError(t, client.ClearDEKSafety(ctx, "/t/app"))
		assert.Equal(t, "/t/app", rpc.lastClear.GetPath())
	})

	t.Run("WarnPercentOutsideZeroToHundredIsRefused", func(t *testing.T) {
		for _, percent := range []int{-1, 101} {
			rpc := &fakeDEKSafetyRPC{}
			err := platformDEKSafety{client: rpc}.SetDEKSafety(ctx, &dekclient.SetDEKSafetyRequest{Path: "/t/app", WarningPercent: percent})
			assert.Equal(t, ErrInvalidDEKWarnPercent{Percent: percent}, err)
			assert.Nil(t, rpc.lastSafety, "an invalid percentage must not reach platformd")
		}
	})

	t.Run("ServiceErrorIsReturned", func(t *testing.T) {
		rpcErr := errors.New("DEK not found")
		client := platformDEKSafety{client: &fakeDEKSafetyRPC{err: rpcErr}}

		_, err := client.SetDefaultDEK(ctx, "/t/app")
		assert.ErrorIs(t, err, rpcErr)
		assert.ErrorIs(t, client.SetDEKSafety(ctx, &dekclient.SetDEKSafetyRequest{Path: "/t/app"}), rpcErr)
		assert.ErrorIs(t, client.ClearDEKSafety(ctx, "/t/app"), rpcErr)
	})
}

func TestDEKSafetyClientFor(t *testing.T) {
	noSDK := func() (dekclient.Client, error) {
		t.Fatal("the SDK DEK client must not be opened on a transport that uses platformd's DEKManagement")
		return nil, nil
	}

	for _, protocol := range []platform.Protocol{platform.ProtocolGRPC, platform.ProtocolUnix, platform.ProtocolQUIC} {
		t.Run("PlatformServiceOver"+protocol.String(), func(t *testing.T) {
			rpc := &fakeDEKSafetyRPC{}
			client, err := dekSafetyClientFor(fakeStatusPlatformClient{protocol: protocol, dek: rpc}, noSDK)
			require.NoError(t, err)

			require.NoError(t, client.ClearDEKSafety(context.Background(), "/t/app"))
			assert.Equal(t, "/t/app", rpc.lastClear.GetPath())
		})
	}

	t.Run("NoPlatformConnectionIsUnavailable", func(t *testing.T) {
		_, err := dekSafetyClientFor(fakeStatusPlatformClient{protocol: platform.ProtocolGRPC}, noSDK)
		assert.ErrorIs(t, err, ErrDEKServiceUnavailable{})
	})

	for _, protocol := range []platform.Protocol{platform.ProtocolREST, platform.ProtocolMCP} {
		t.Run("SDKClientOver"+protocol.String(), func(t *testing.T) {
			sdk := &fakeDEKClient{}
			client, err := dekSafetyClientFor(fakeStatusPlatformClient{protocol: protocol},
				func() (dekclient.Client, error) { return sdk, nil })
			require.NoError(t, err)
			assert.Same(t, sdk, client)
		})
	}

	t.Run("SDKClientErrorStopsTheCommand", func(t *testing.T) {
		sdkErr := errors.New("quicbaas not configured")
		_, err := dekSafetyClientFor(fakeStatusPlatformClient{protocol: platform.ProtocolREST},
			func() (dekclient.Client, error) { return nil, sdkErr })
		assert.ErrorIs(t, err, sdkErr)
	})
}

func TestSetDEKSafetyClientFactory(t *testing.T) {
	t.Run("OverrideAndRestore", func(t *testing.T) {
		fake := &fakeDEKClient{}
		restore := setDEKSafetyClientFactory(func(*cli.BaseCommand) (dekSafetyClient, error) { return fake, nil })

		client, err := activeDEKSafetyClientFactory(nil)
		require.NoError(t, err)
		assert.Same(t, fake, client)

		restore()
		assert.NotNil(t, activeDEKSafetyClientFactory)
	})

	t.Run("FactoryErrorStopsTheCommand", func(t *testing.T) {
		factoryErr := errors.New("no daemon")
		restore := setDEKSafetyClientFactory(func(*cli.BaseCommand) (dekSafetyClient, error) { return nil, factoryErr })
		defer restore()

		_, err := activeDEKSafetyClientFactory(nil)
		assert.ErrorIs(t, err, factoryErr)
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
		"create":        {"create", "/t/app"},
		"create limits": {"create", "/t/app", "--max-operations", "10", "--max-bytes", "20", "--warn-percent", "70"},
		"get":           {"get", "/t/app"},
		"list":          {"list", "--prefix", "/t", "--recursive", "--limit", "5"},
		"delete":        {"delete", "/t/app", "--force"},
		"rotate":        {"rotate", "/t/app"},
		"status":        {"status", "/t/app"},
		"set-default":   {"set-default", "/t/app"},
		"set-safety":    {"set-safety", "/t/app", "--max-operations", "10", "--max-bytes", "20", "--warn-percent", "70"},
		"clear-safety":  {"clear-safety", "/t/app", "--force"},
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
