package device

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	devicesvc "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// realIssuerDeviceID is the one device the real issuer's store holds.
const realIssuerDeviceID uint64 = 7

// startRealIssuerServer serves the daemon's own DeviceGRPCService, over a
// real in-memory device service holding one device, on a Unix socket. The
// CLI then talks to the issuer that runs in platformd, not a fake that
// decides which ids exist (#2136, Codex round 1 P1).
func startRealIssuerServer(t *testing.T) func(cli.OutputFormat) *cli.CommonFlags {
	t.Helper()
	ctx := context.Background()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(ctx))
	logger := logging.NewLogger(slog.LevelError, nil)
	devices, err := devicesvc.NewService(devicesvc.NewDatastore(storage, logger))
	require.NoError(t, err)
	require.NoError(t, devices.Create(ctx,
		&entities.Device{ID: realIssuerDeviceID, Serial: "SN-REAL-ISSUER", Model: "test-model"}))

	sock := filepath.Join(shortSocketDir(t), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	gs := grpc.NewServer()
	platformv1.RegisterDeviceServiceServer(gs, daemon.NewDeviceGRPCService(devices, nil, nil))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return func(format cli.OutputFormat) *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}
}

func TestRunAttestChallenge_RealIssuer(t *testing.T) {
	flags := startRealIssuerServer(t)

	t.Run("KnownDevice", func(t *testing.T) {
		out, err := captureStdout(t, func() error {
			return runAttestChallenge(flags(cli.OutputFormatJSON), "7")
		})
		require.NoError(t, err)
		var got struct {
			DeviceID    uint64 `json:"device_id"`
			ChallengeID string `json:"challenge_id"`
			Nonce       string `json:"nonce"`
		}
		require.NoError(t, json.Unmarshal([]byte(out), &got), "output %q", out)
		assert.Equal(t, realIssuerDeviceID, got.DeviceID)
		assert.NotEmpty(t, got.ChallengeID)
		assert.NotEmpty(t, got.Nonce)
	})

	t.Run("UnknownDevice", func(t *testing.T) {
		assert.Equal(t, ErrDeviceNotFound{ID: 4242}, runAttestChallenge(flags(cli.OutputFormatJSON), "4242"))
	})
}
