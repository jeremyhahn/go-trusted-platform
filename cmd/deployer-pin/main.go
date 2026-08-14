// Command deployer-pin provisions a local SSH host-key pin envelope for the
// bootstrap deployer / switch / fabric known_hosts store.
//
// The deployer SSH stack is fail-closed: it verifies the target host key
// against a pinned envelope resolved from the directory containing
// deployer.known_hosts_path, under (scope=service, owner=host, host). No
// trust-on-first-use path exists. This tool captures the host key the Go
// x/crypto/ssh stack actually negotiates against the target (matching what
// the deployer will see) and persists the pin via the go-quicbaas SDK
// knownhosts re-export.
//
// Idempotent: an identical existing pin is left in place; a differing pin is
// rotated (removed then re-added).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	knownhosts "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/knownhosts"
	sshscope "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ssh/scope"
	filestorage "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/storage/file"
	"golang.org/x/crypto/ssh"
)

var errCaptured = errors.New("host key captured")

func main() {
	var (
		host  = flag.String("host", "", "target host (IP or hostname) to pin")
		port  = flag.Int("port", 22, "target SSH port")
		owner = flag.String("owner", "", "pin owner (defaults to --host)")
		dir   = flag.String("dir", "", "known_hosts store root directory (the directory containing known_hosts_path)")
	)
	flag.Parse()

	if *host == "" || *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: deployer-pin --host <ip> --dir <known_hosts_dir> [--owner <ip>] [--port 22]")
		os.Exit(2)
	}
	ownerVal := *owner
	if ownerVal == "" {
		ownerVal = *host
	}

	pub, err := captureHostKey(*host, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capture host key: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir store dir: %v\n", err)
		os.Exit(1)
	}
	backend, err := filestorage.New(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store backend: %v\n", err)
		os.Exit(1)
	}
	store, err := knownhosts.NewBackendStore(backend)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open known_hosts store: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pin := knownhosts.PinFromPublicKey(*host, sshscope.Service, ownerVal, pub, "manual")

	if existing, gerr := store.Get(ctx, sshscope.Service, ownerVal, *host); gerr == nil && existing != nil {
		if existing.Fingerprint == pin.Fingerprint {
			fmt.Printf("already pinned: host=%s owner=%s %s %s\n", *host, ownerVal, pin.Algorithm, pin.Fingerprint)
			return
		}
		if rerr := store.Remove(ctx, sshscope.Service, ownerVal, *host); rerr != nil {
			fmt.Fprintf(os.Stderr, "rotate (remove stale pin): %v\n", rerr)
			os.Exit(1)
		}
	}

	if err := store.Add(ctx, pin); err != nil {
		fmt.Fprintf(os.Stderr, "add pin: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("pinned: host=%s owner=%s scope=service %s %s\n", *host, ownerVal, pin.Algorithm, pin.Fingerprint)
}

// captureHostKey dials the target with the Go x/crypto/ssh handshake and
// returns the host key the server presents. Authentication is never attempted;
// the host-key callback fires during key exchange, captures the key, and
// aborts the handshake.
func captureHostKey(host string, port int) (ssh.PublicKey, error) {
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return errCaptured
		},
		Timeout: 10 * time.Second,
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	_, derr := ssh.Dial("tcp", addr, cfg)
	if captured != nil {
		return captured, nil
	}
	return nil, fmt.Errorf("no host key captured: %w", derr)
}
