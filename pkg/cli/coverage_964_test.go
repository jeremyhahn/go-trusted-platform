package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cov964Cause is the cause wrapped by the typed errors under test.
var cov964Cause = errors.New("cov964 cause")

// cov964PKI holds the PEM files of an in-memory CA and a client
// certificate it signed, written under a test temp directory.
type cov964PKI struct {
	caCert     string
	clientCert string
	clientKey  string
}

// cov964WritePEM writes one PEM block to dir/name and returns the path.
func cov964WritePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// cov964NewPKI generates a CA and a client certificate in memory.
func cov964NewPKI(t *testing.T) cov964PKI {
	t.Helper()
	dir := t.TempDir()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cov964 CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "cov964 client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	return cov964PKI{
		caCert:     cov964WritePEM(t, dir, "ca.pem", "CERTIFICATE", caDER),
		clientCert: cov964WritePEM(t, dir, "client.pem", "CERTIFICATE", clientDER),
		clientKey:  cov964WritePEM(t, dir, "client-key.pem", "EC PRIVATE KEY", keyDER),
	}
}

func TestCov964TypedErrorMessagesAndCauses(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		message string
		wraps   bool
	}{
		{
			name:    "embedded host unavailable",
			err:     ErrEmbeddedHostUnavailable{},
			message: "the embedded transport needs platformd hosted in this process, and this command cannot host it",
		},
		{
			name:    "CA certificate load failed",
			err:     ErrTLSCACertLoadFailed{Path: "/x/ca.pem", Err: cov964Cause},
			message: "failed to load CA certificate /x/ca.pem: cov964 cause",
			wraps:   true,
		},
		{
			name:    "CA certificate invalid",
			err:     ErrTLSCACertInvalid{Path: "/x/ca.pem"},
			message: "CA certificate file contains no valid PEM data: /x/ca.pem",
		},
		{
			name:    "wrapped error",
			err:     &WrappedError{Msg: "loading", Err: cov964Cause},
			message: "loading: cov964 cause",
			wraps:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.message {
				t.Errorf("Error() = %q, want %q", got, tt.message)
			}
			if got := errors.Is(tt.err, cov964Cause); got != tt.wraps {
				t.Errorf("errors.Is(cause) = %v, want %v", got, tt.wraps)
			}
		})
	}
}

func TestCov964TLSCACertLoadFailedUnwrapsToPathError(t *testing.T) {
	err := error(ErrTLSCACertLoadFailed{Path: "missing", Err: &fs.PathError{Op: "open", Path: "missing", Err: fs.ErrNotExist}})

	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("errors.As(*fs.PathError) failed for %v", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("errors.Is(fs.ErrNotExist) = false for %v", err)
	}
}

func TestCov964OutputWritesInPrinterFormat(t *testing.T) {
	var buf bytes.Buffer
	cmd := &BaseCommand{printer: NewPrinterWithWriter(OutputFormatJSON, true, &buf)}

	if err := cmd.Output(map[string]string{"name": "cov964"}); err != nil {
		t.Fatalf("Output() error = %v", err)
	}
	want := "{\n  \"name\": \"cov964\"\n}\n"
	if got := buf.String(); got != want {
		t.Errorf("Output() wrote %q, want %q", got, want)
	}
}

func TestCov964OutputRejectsUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	cmd := &BaseCommand{printer: NewPrinterWithWriter(OutputFormat("xml"), true, &buf)}

	err := cmd.Output("value")
	var formatErr ErrInvalidOutputFormat
	if !errors.As(err, &formatErr) {
		t.Fatalf("Output() error = %v, want ErrInvalidOutputFormat", err)
	}
	if formatErr.Format != "xml" {
		t.Errorf("Format = %q, want %q", formatErr.Format, "xml")
	}
	if buf.Len() != 0 {
		t.Errorf("Output() wrote %q on error, want nothing", buf.String())
	}
}

func TestCov964PrintlnWritesRawLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "multi-line report kept verbatim", in: "TPM\n  vendor: x", want: "TPM\n  vendor: x\n"},
		{name: "empty line", in: "", want: "\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			NewPrinterWithWriter(OutputFormatTable, true, &buf).Println(tt.in)
			if got := buf.String(); got != tt.want {
				t.Errorf("Println() wrote %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCov964BuildTLSConfigModes(t *testing.T) {
	pki := cov964NewPKI(t)

	t.Run("no files means no TLS", func(t *testing.T) {
		cfg, err := buildTLSConfig("", "", "")
		if err != nil || cfg != nil {
			t.Fatalf("buildTLSConfig() = %v, %v, want nil, nil", cfg, err)
		}
	})

	t.Run("CA only verifies the server without a client certificate", func(t *testing.T) {
		cfg, err := buildTLSConfig(pki.caCert, "", "")
		if err != nil {
			t.Fatalf("buildTLSConfig() error = %v", err)
		}
		if cfg.RootCAs == nil {
			t.Error("RootCAs is nil")
		}
		if len(cfg.Certificates) != 0 {
			t.Errorf("Certificates = %d, want 0", len(cfg.Certificates))
		}
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
		}
	})

	t.Run("mutual TLS carries the client certificate", func(t *testing.T) {
		cfg, err := buildTLSConfig(pki.caCert, pki.clientCert, pki.clientKey)
		if err != nil {
			t.Fatalf("buildTLSConfig() error = %v", err)
		}
		if cfg.RootCAs == nil {
			t.Error("RootCAs is nil")
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
		}
		leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatalf("parse client certificate: %v", err)
		}
		if leaf.Subject.CommonName != "cov964 client" {
			t.Errorf("client CN = %q, want %q", leaf.Subject.CommonName, "cov964 client")
		}
	})

	t.Run("client certificate without its key fails", func(t *testing.T) {
		cfg, err := buildTLSConfig(pki.caCert, pki.clientCert, "")
		if err == nil {
			t.Fatalf("buildTLSConfig() = %v, want an error", cfg)
		}
		if cfg != nil {
			t.Errorf("buildTLSConfig() config = %v on error, want nil", cfg)
		}
	})

	t.Run("missing client certificate file fails", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.pem")
		if cfg, err := buildTLSConfig(pki.caCert, missing, pki.clientKey); err == nil {
			t.Fatalf("buildTLSConfig() = %v, want an error", cfg)
		}
	})
}

func TestCov964BuildCACertOnlyTLSConfigErrors(t *testing.T) {
	dir := t.TempDir()
	malformed := filepath.Join(dir, "malformed.pem")
	if err := os.WriteFile(malformed, []byte("not a certificate"), 0600); err != nil {
		t.Fatalf("write malformed PEM: %v", err)
	}
	missing := filepath.Join(dir, "absent.pem")

	t.Run("missing file", func(t *testing.T) {
		_, err := buildCACertOnlyTLSConfig(missing)
		var loadErr ErrTLSCACertLoadFailed
		if !errors.As(err, &loadErr) {
			t.Fatalf("error = %v, want ErrTLSCACertLoadFailed", err)
		}
		if loadErr.Path != missing {
			t.Errorf("Path = %q, want %q", loadErr.Path, missing)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("errors.Is(fs.ErrNotExist) = false for %v", err)
		}
	})

	t.Run("malformed PEM", func(t *testing.T) {
		_, err := buildCACertOnlyTLSConfig(malformed)
		var invalidErr ErrTLSCACertInvalid
		if !errors.As(err, &invalidErr) {
			t.Fatalf("error = %v, want ErrTLSCACertInvalid", err)
		}
		if invalidErr.Path != malformed {
			t.Errorf("Path = %q, want %q", invalidErr.Path, malformed)
		}
	})
}

func TestCov964ResolveContextQuicBaaSTLS(t *testing.T) {
	pki := cov964NewPKI(t)

	tests := []struct {
		name      string
		ctx       *Context
		wantTLS   bool
		wantCerts int
	}{
		{
			name: "local context uses the quicbaas files",
			ctx: &Context{Type: ContextTypeLocal, Local: &LocalContext{
				QuicBaaSCACert: pki.caCert, QuicBaaSClientCert: pki.clientCert, QuicBaaSClientKey: pki.clientKey,
			}},
			wantTLS:   true,
			wantCerts: 1,
		},
		{
			name:      "remote context uses its own files",
			ctx:       &Context{Type: ContextTypeRemote, Remote: &RemoteContext{CACert: pki.caCert}},
			wantTLS:   true,
			wantCerts: 0,
		},
		{
			name: "remote context without its section has no TLS",
			ctx:  &Context{Type: ContextTypeRemote},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := resolveContextQuicBaaSTLS(tt.ctx)
			if err != nil {
				t.Fatalf("resolveContextQuicBaaSTLS() error = %v", err)
			}
			if (cfg != nil) != tt.wantTLS {
				t.Fatalf("config present = %v, want %v", cfg != nil, tt.wantTLS)
			}
			if cfg != nil && len(cfg.Certificates) != tt.wantCerts {
				t.Errorf("Certificates = %d, want %d", len(cfg.Certificates), tt.wantCerts)
			}
		})
	}
}

func TestCov964ResolveContextQuicBaaSTLSPropagatesError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	ctx := &Context{Type: ContextTypeLocal, Local: &LocalContext{QuicBaaSCACert: missing}}

	_, err := resolveContextQuicBaaSTLS(ctx)
	var loadErr ErrTLSCACertLoadFailed
	if !errors.As(err, &loadErr) {
		t.Fatalf("error = %v, want ErrTLSCACertLoadFailed", err)
	}
}

func TestCov964DefaultConfigPathUsesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	want := filepath.Join(home, ".platformctl", "config.yaml")
	if got := DefaultConfigPath(); got != want {
		t.Errorf("DefaultConfigPath() = %q, want %q", got, want)
	}
}

func TestCov964DefaultConfigPathFallsBackWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")

	if got := DefaultConfigPath(); got != SystemConfigPath {
		t.Errorf("DefaultConfigPath() = %q, want %q", got, SystemConfigPath)
	}
}

func TestCov964SaveAndLoadDefaultPathRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	config := DefaultConfig()
	config.AddContext(&Context{Name: "cov964", Type: ContextTypeRemote, Remote: &RemoteContext{Server: "https://cov964.example:8443"}})
	if err := config.SetCurrentContext("cov964"); err != nil {
		t.Fatalf("SetCurrentContext() error = %v", err)
	}
	if err := config.Save(""); err != nil {
		t.Fatalf("Save(\"\") error = %v", err)
	}

	path := filepath.Join(home, ".platformctl", "config.yaml")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("saved config not at the default path: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("config mode = %o, want 600", perm)
	}

	loaded, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig(\"\") error = %v", err)
	}
	current, err := loaded.GetCurrentContext()
	if err != nil {
		t.Fatalf("GetCurrentContext() error = %v", err)
	}
	if current.Remote == nil || current.Remote.Server != "https://cov964.example:8443" {
		t.Errorf("current context = %+v, want the saved remote", current)
	}
}

func TestCov964LoadConfigErrors(t *testing.T) {
	dir := t.TempDir()
	unparsable := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(unparsable, []byte("contexts: [unterminated"), 0600); err != nil {
		t.Fatalf("write bad config: %v", err)
	}

	t.Run("a directory cannot be read", func(t *testing.T) {
		_, err := LoadConfig(dir)
		var readErr ErrConfigReadFailed
		if !errors.As(err, &readErr) {
			t.Fatalf("error = %v, want ErrConfigReadFailed", err)
		}
		if readErr.Path != dir {
			t.Errorf("Path = %q, want %q", readErr.Path, dir)
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		_, err := LoadConfig(unparsable)
		var parseErr ErrConfigParseFailed
		if !errors.As(err, &parseErr) {
			t.Fatalf("error = %v, want ErrConfigParseFailed", err)
		}
	})

	t.Run("missing file yields defaults bound to the path", func(t *testing.T) {
		missing := filepath.Join(dir, "absent.yaml")
		config, err := LoadConfig(missing)
		if err != nil {
			t.Fatalf("LoadConfig() error = %v", err)
		}
		if config.CurrentContext != DefaultConfig().CurrentContext {
			t.Errorf("CurrentContext = %q, want the default", config.CurrentContext)
		}
		if err := config.Save(""); err != nil {
			t.Fatalf("Save(\"\") error = %v", err)
		}
		if _, err := os.Stat(missing); err != nil {
			t.Errorf("Save(\"\") did not write the loaded path: %v", err)
		}
	})
}

func TestCov964SaveErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	t.Run("parent is a file", func(t *testing.T) {
		err := DefaultConfig().Save(filepath.Join(blocker, "config.yaml"))
		var dirErr ErrConfigDirCreateFailed
		if !errors.As(err, &dirErr) {
			t.Fatalf("error = %v, want ErrConfigDirCreateFailed", err)
		}
	})

	t.Run("target is a directory", func(t *testing.T) {
		err := DefaultConfig().Save(dir)
		var writeErr ErrConfigWriteFailed
		if !errors.As(err, &writeErr) {
			t.Fatalf("error = %v, want ErrConfigWriteFailed", err)
		}
		if writeErr.Path != dir {
			t.Errorf("Path = %q, want %q", writeErr.Path, dir)
		}
	})
}

func TestCov964AutoDetectContext(t *testing.T) {
	t.Run("remote from the environment", func(t *testing.T) {
		t.Setenv("PLATFORMCTL_SERVER", "https://cov964.example:8443")
		t.Setenv("PLATFORMCTL_CA_CERT", "/x/ca.pem")
		t.Setenv("PLATFORMCTL_CLIENT_CERT", "/x/client.pem")
		t.Setenv("PLATFORMCTL_CLIENT_KEY", "/x/client-key.pem")

		ctx, err := AutoDetectContext()
		if err != nil {
			t.Fatalf("AutoDetectContext() error = %v", err)
		}
		if ctx.Type != ContextTypeRemote || ctx.Name != "remote-auto" {
			t.Fatalf("context = %s/%s, want remote-auto/remote", ctx.Name, ctx.Type)
		}
		want := RemoteContext{
			Server:     "https://cov964.example:8443",
			CACert:     "/x/ca.pem",
			ClientCert: "/x/client.pem",
			ClientKey:  "/x/client-key.pem",
		}
		got := *ctx.Remote
		if got.Server != want.Server || got.CACert != want.CACert || got.ClientCert != want.ClientCert || got.ClientKey != want.ClientKey {
			t.Errorf("remote = %+v, want %+v", got, want)
		}
	})

	t.Run("nothing configured", func(t *testing.T) {
		t.Setenv("PLATFORMCTL_SERVER", "")

		_, err := AutoDetectContext()
		var detectErr ErrAutoDetectionFailed
		if !errors.As(err, &detectErr) {
			t.Fatalf("error = %v, want ErrAutoDetectionFailed", err)
		}
		if !strings.Contains(detectErr.Reason, "no remote server configured") {
			t.Errorf("Reason = %q", detectErr.Reason)
		}
	})
}
