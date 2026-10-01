package diskimage

import (
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestKMSClients(t *testing.T) {
	t.Run("no context is an error, not a nil client", func(t *testing.T) {
		clients, err := kmsClients(cli.NewLazyClient(&cli.CommonFlags{}))()
		var noCtx cli.ErrNoContextSet
		if !errors.As(err, &noCtx) || clients != nil {
			t.Fatalf("kmsClients() = %v, %v", clients, err)
		}
	})

	t.Run("a context yields the KMS and CA clients", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "platformd.sock")
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		lazy := cli.NewLazyClient(&cli.CommonFlags{GetContext: func() (*cli.Context, error) {
			return &cli.Context{Name: "local", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: socket}}, nil
		}})
		defer func() {
			if err := lazy.Close(); err != nil {
				t.Error(err)
			}
		}()
		clients, err := kmsClients(lazy)()
		if err != nil {
			t.Fatalf("kmsClients: %v", err)
		}
		if clients.KMS == nil || clients.CA == nil {
			t.Fatalf("clients = %+v", clients)
		}
	})
}
