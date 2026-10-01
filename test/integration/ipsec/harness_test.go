//go:build integration

package ipsec

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Paths inside a peer's root filesystem.
const (
	// p11Socket is where the peer's p11-kit server listens; charon and
	// pkcs11-tool reach the module through it.
	p11Socket = "/run/p11-kit/xkms.sock"
	// p11Client is the PKCS#11 module charon loads.
	p11Client = "/usr/lib/pkcs11/p11-kit-client.so"
	// moduleInHost is the go-xkms module inside the module host.
	moduleInHost = "/usr/lib/xkms/libxkms_pkcs11.so"
	// charonLog is the file log the suite configures.
	charonLog = "/var/log/charon.log"
	// charonPID is the pidfile charon writes itself.
	charonPID = "/run/charon.pid"
	// viciSocket is charon's VICI control socket.
	viciSocket = "/run/charon.vici"
)

// Token credentials. The PINs exist only inside the test; a node's PIN
// reaches charon over VICI (plan §5.2), never from a file. The user PIN keys
// the module's sealed key store, so it is at least the 12 characters the
// seal recommends.
const (
	soPIN    = "suite-so-pin-0001"
	userPIN  = "suite-user-pin-0001"
	keyID    = "01"
	keyLabel = "ike"
)

// CommandError reports a command that failed, with what it printed.
type CommandError struct {
	Command string
	Output  string
	Err     error
}

func (e *CommandError) Error() string {
	return "ipsec suite: " + e.Command + ": " + e.Err.Error() + "\n" + e.Output
}

func (e *CommandError) Unwrap() error { return e.Err }

// WaitError reports a condition that did not become true in time.
type WaitError struct {
	What string
	Err  error
}

func (e *WaitError) Error() string {
	return "ipsec suite: waiting for " + e.What + ": " + e.Err.Error()
}

func (e *WaitError) Unwrap() error { return e.Err }

// run executes a command and returns its combined output.
func run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// A daemon a command starts may inherit its output pipe; without a
	// bound, CombinedOutput would wait for that daemon instead of the
	// command.
	cmd.WaitDelay = 10 * time.Second
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), &CommandError{Command: name + " " + strings.Join(args, " "), Output: string(out), Err: err}
	}
	return string(out), nil
}

// mustRun is run for steps whose failure ends the test.
func mustRun(t *testing.T, ctx context.Context, name string, args ...string) string {
	t.Helper()
	out, err := run(ctx, nil, name, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// waitFor polls cond until it reports true, it fails, or ctx ends. Polling
// is the honest primitive here: the conditions are files and kernel state
// owned by other processes, with nothing to subscribe to.
func waitFor(ctx context.Context, what string, cond func() (bool, error)) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		ok, err := cond()
		if err != nil {
			return &WaitError{What: what, Err: err}
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return &WaitError{What: what, Err: ctx.Err()}
		case <-ticker.C:
		}
	}
}

// fileExists is a waitFor condition.
func fileExists(path string) func() (bool, error) {
	return func() (bool, error) {
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return err == nil, err
	}
}

// peer is one IPsec endpoint: an Alpine root filesystem in its own network
// namespace, with its own token behind its own p11-kit server.
type peer struct {
	name string
	root string
	// host is the peer's module host: the glibc root filesystem whose
	// p11-kit server hosts the go-xkms module for this peer only.
	host  string
	netns string
	addr  string
	work  string
	// pub is the IKE public key on the peer's token, once provisioned.
	pub *ecdsa.PublicKey
}

// path maps a path inside the peer's root filesystem to the host.
func (p *peer) path(inside string) string { return filepath.Join(p.root, inside) }

// chroot runs a command inside the peer's root filesystem and network
// namespace.
func (p *peer) chroot(ctx context.Context, env []string, args ...string) (string, error) {
	full := append([]string{"netns", "exec", p.netns, "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, env...)
	full = append(full, "chroot", p.root)
	full = append(full, args...)
	return run(ctx, nil, "ip", full...)
}

// p11Env points a PKCS#11 consumer inside the root at the peer's server.
func p11Env() []string { return []string{"P11_KIT_SERVER_ADDRESS=unix:path=" + p11Socket} }

// mount mounts and registers the unmount for cleanup.
func mount(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	mustRun(t, ctx, "mount", args...)
	target := args[len(args)-1]
	t.Cleanup(func() {
		if out, err := run(context.Background(), nil, "umount", "-l", target); err != nil {
			t.Logf("cleanup: %v %s", err, out)
		}
	})
}

// unpack extracts a root filesystem tarball into dir and mounts the
// pseudo-filesystems and the /run tmpfs a chroot into it needs.
func unpack(t *testing.T, ctx context.Context, tarball, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustRun(t, ctx, "tar", "-xpf", tarball, "-C", dir)
	mount(t, ctx, "-t", "proc", "proc", filepath.Join(dir, "proc"))
	mount(t, ctx, "-t", "sysfs", "sysfs", filepath.Join(dir, "sys"))
	mount(t, ctx, "--bind", "/dev", filepath.Join(dir, "dev"))
	mount(t, ctx, "-t", "tmpfs", "tmpfs", filepath.Join(dir, "run"))
}

// newPeer unpacks the root filesystem, and the peer's own module host beside
// it. Everything is undone at cleanup.
func newPeer(t *testing.T, ctx context.Context, in inputs, name, addr string) *peer {
	t.Helper()
	p := &peer{
		name:  name,
		addr:  addr,
		netns: "tp-ipsec-" + name,
		work:  filepath.Join(in.workDir, t.Name(), name),
	}
	p.root = filepath.Join(p.work, "root")
	p.host = filepath.Join(p.work, "modulehost")
	if err := os.RemoveAll(p.work); err != nil {
		t.Fatal(err)
	}
	unpack(t, ctx, in.rootfs, p.root)
	unpack(t, ctx, in.moduleHost, p.host)
	return p
}

// link creates a and b's network namespaces joined by a veth pair.
func link(t *testing.T, ctx context.Context, a, b *peer) {
	t.Helper()
	for _, p := range []*peer{a, b} {
		_, _ = run(ctx, nil, "ip", "netns", "del", p.netns) // a previous run's leftovers
		mustRun(t, ctx, "ip", "netns", "add", p.netns)
		ns := p.netns
		t.Cleanup(func() {
			if out, err := run(context.Background(), nil, "ip", "netns", "del", ns); err != nil {
				t.Logf("cleanup: %v %s", err, out)
			}
		})
	}
	va, vb := "veth-"+a.name, "veth-"+b.name
	mustRun(t, ctx, "ip", "link", "add", va, "netns", a.netns, "type", "veth", "peer", "name", vb, "netns", b.netns)
	for _, p := range []*peer{a, b} {
		dev := "veth-" + p.name
		mustRun(t, ctx, "ip", "-n", p.netns, "addr", "add", p.addr+"/24", "dev", dev)
		mustRun(t, ctx, "ip", "-n", p.netns, "link", "set", dev, "up")
		mustRun(t, ctx, "ip", "-n", p.netns, "link", "set", "lo", "up")
	}
}

// startModuleServer starts the peer's p11-kit server in its module host,
// hosting the go-xkms module with the peer's own token. The socket
// directory is shared into the peer's root, and the socket is handed to the
// strongswan user: charon talks to it after it has dropped root.
func (p *peer) startModuleServer(t *testing.T, ctx context.Context) {
	t.Helper()
	dir := filepath.Dir(p11Socket)
	for _, root := range []string{p.root, p.host} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mount(t, ctx, "--bind", p.path(dir), filepath.Join(p.host, dir))
	cmd := exec.Command("chroot", p.host,
		"p11-kit", "server", "-f", "-n", p11Socket, "--provider", moduleInHost, "pkcs11:")
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"XKMS_PKCS11_MODE=local",
		"XKMS_PKCS11_SEAL_STRATEGY=passphrase",
		"XKMS_PKCS11_LOCAL_KEYDIR=/var/lib/xkms/keys",
		"XKMS_PKCS11_STORAGE_PATH=/var/lib/xkms/state",
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(&CommandError{Command: "p11-kit server", Err: err})
	}
	t.Cleanup(func() {
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("cleanup: p11-kit server: %v", err)
		}
		_ = cmd.Wait() // killed; its exit status says only that
		t.Logf("p11-kit server (%s):\n%s", p.name, output.String())
	})
	sock := p.path(p11Socket)
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := waitFor(wctx, "the p11-kit server socket of "+p.name, fileExists(sock)); err != nil {
		t.Fatal(err)
	}
	uid, gid := p.lookupUser(t, "strongswan")
	if err := os.Chown(sock, uid, gid); err != nil {
		t.Fatal(err)
	}
}

// lookupUser reads a user's uid and gid from the peer's /etc/passwd.
func (p *peer) lookupUser(t *testing.T, name string) (int, int) {
	t.Helper()
	f, err := os.Open(p.path("/etc/passwd"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(s.Text(), ":")
		if len(fields) < 4 || fields[0] != name {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			t.Fatal(err)
		}
		gid, err := strconv.Atoi(fields[3])
		if err != nil {
			t.Fatal(err)
		}
		return uid, gid
	}
	t.Fatalf("user %s is not in %s's /etc/passwd", name, p.name)
	return 0, 0
}

// provisionToken initializes the peer's token and generates the IKE key
// pair on it through p11-kit-client.so -- the same path charon uses -- and
// returns the public key.
func (p *peer) provisionToken(t *testing.T, ctx context.Context) *ecdsa.PublicKey {
	t.Helper()
	tool := []string{"pkcs11-tool", "--module", p11Client}
	steps := [][]string{
		{"--init-token", "--label", "vtep-" + p.name, "--so-pin", soPIN},
		{"--init-pin", "--so-pin", soPIN, "--pin", userPIN},
		{"--login", "--pin", userPIN, "--keypairgen", "--key-type", "EC:prime256v1", "--id", keyID, "--label", keyLabel},
		// The module's key store is sealed under the user PIN, so even the
		// public half is read in a logged-in session.
		{"--login", "--pin", userPIN, "--read-object", "--type", "pubkey", "--id", keyID, "-o", "/tmp/ike.pub.der"},
	}
	for _, step := range steps {
		if _, err := p.chroot(ctx, p11Env(), append(tool, step...)...); err != nil {
			t.Fatal(err)
		}
	}
	der, err := os.ReadFile(p.path("/tmp/ike.pub.der"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the token's IKE key is %T, not ECDSA", pub)
	}
	return key
}

// testCA is a throwaway issuing CA for one test.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ipsec suite CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// idIPsecIKE is id-kp-ipsecIKE (RFC 4945), the EKU the plan's ipsec-vtep
// profile issues.
var idIPsecIKE = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 17}

// issue certifies a peer's token-held public key with its fabric address
// as the only identity.
func (ca *testCA) issue(t *testing.T, p *peer, pub *ecdsa.PublicKey, serial int64) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(serial),
		Subject:            pkix.Name{CommonName: "vtep-" + p.name},
		IPAddresses:        []net.IP{net.ParseIP(p.addr)},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{idIPsecIKE},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeFile writes a file inside the peer's root filesystem.
func (p *peer) writeFile(t *testing.T, inside string, data []byte, mode os.FileMode) {
	t.Helper()
	path := p.path(inside)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

// configure writes the peer's credentials, strongSwan settings and one
// transport-mode connection to remote: ECDSA public-key authentication
// with the private key on the token, identities that are the fabric
// addresses (the certificates' only SANs), AES-256-GCM with an ML-KEM-768
// hybrid key exchange (RFC 9370) for IKE and the CHILD_SA rekey, extended
// sequence numbers and a 1024-packet replay window (plan §5.2 Proposals).
func (p *peer) configure(t *testing.T, ca *testCA, cert []byte, remote *peer) {
	t.Helper()
	p.writeFile(t, "/etc/swanctl/x509ca/ca.pem", ca.pem, 0o644)
	p.writeFile(t, "/etc/swanctl/x509/vtep.pem", cert, 0o644)
	p.writeFile(t, "/etc/strongswan.d/charon/pkcs11.conf", []byte(`pkcs11 {
    load = yes
    modules {
        xkms {
            path = `+p11Client+`
        }
    }
}
`), 0o644)
	p.writeFile(t, "/etc/strongswan.d/charon-logging.conf", []byte(`charon {
    filelog {
        suite {
            path = `+charonLog+`
            default = 1
            ike = 2
            cfg = 2
            lib = 2
            time_format = %b %e %T
        }
    }
}
`), 0o644)
	p.writeFile(t, "/etc/conf.d/charon", []byte(`export P11_KIT_SERVER_ADDRESS="unix:path=`+p11Socket+`"
`), 0o644)
	p.writeFile(t, "/etc/swanctl/swanctl.conf", []byte(`connections {
    vtep-`+remote.name+` {
        version = 2
        local_addrs = `+p.addr+`
        remote_addrs = `+remote.addr+`
        proposals = aes256gcm16-prfsha384-ecp384-ke1_mlkem768
        local {
            auth = pubkey
            certs = vtep.pem
            id = `+p.addr+`
        }
        remote {
            auth = pubkey
            id = `+remote.addr+`
        }
        children {
            fabric {
                mode = transport
                esp_proposals = aes256gcm16-ecp384-ke1_mlkem768-esn
                replay_window = 1024
            }
        }
    }
}
secrets {
    token-ike {
        handle = `+keyID+`
        module = xkms
        pin = `+userPIN+`
    }
}
`), 0o600)
}

// startCharon starts charon with the packaged OpenRC service and waits for
// its VICI socket. It is stopped the same way at cleanup.
func (p *peer) startCharon(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := os.MkdirAll(p.path("/run/openrc"), 0o755); err != nil {
		t.Fatal(err)
	}
	p.writeFile(t, "/run/openrc/softlevel", nil, 0o644)
	if out, err := p.chroot(ctx, nil, "rc-service", "charon", "start"); err != nil {
		t.Fatalf("%v\n%s", err, p.log())
	} else {
		t.Logf("%s: rc-service charon start:\n%s", p.name, out)
	}
	t.Cleanup(func() {
		sctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		// supervise-daemon --stop waits for the supervisor's PID to vanish,
		// which needs a reaping PID 1 (the Makefile runs the suite with
		// --init); the process table says which process held it up.
		if out, err := p.chroot(sctx, nil, "rc-service", "charon", "stop"); err != nil {
			ps, _ := run(context.Background(), nil, "ps", "-eo", "pid,ppid,stat,args")
			t.Errorf("%s: rc-service charon stop: %v\n%s\nprocesses:\n%s", p.name, err, out, ps)
		}
		t.Logf("charon log (%s):\n%s", p.name, p.log())
	})
	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := waitFor(wctx, "the VICI socket of "+p.name, fileExists(p.path(viciSocket))); err != nil {
		t.Fatalf("%v\n%s", err, p.log())
	}
}

// log returns charon's file log.
func (p *peer) log() string {
	data, err := os.ReadFile(p.path(charonLog))
	if err != nil {
		return "(no charon log: " + err.Error() + ")"
	}
	return string(data)
}

// swanctl runs swanctl inside the peer.
func (p *peer) swanctl(ctx context.Context, args ...string) (string, error) {
	return p.chroot(ctx, nil, append([]string{"swanctl"}, args...)...)
}

// charonStatus returns the running charon's /proc status fields.
func (p *peer) charonStatus(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(p.path(charonPID))
	if err != nil {
		t.Fatal(err)
	}
	pid := strings.TrimSpace(string(data))
	status, err := os.ReadFile(filepath.Join("/proc", pid, "status"))
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	return fields
}
