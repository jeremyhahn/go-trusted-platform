package tpm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	idevidsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/idevid"
)

// cov964Created is a fixed key/certificate timestamp (2023-11-14T22:13:20Z).
const cov964Created int64 = 1700000000

// cov964RPCError is the transport failure the fake daemon returns.
type cov964RPCError struct {
	Op string
}

func (e cov964RPCError) Error() string {
	return "rpc " + e.Op + " unavailable"
}

// cov964GRPC is an in-memory IDevID daemon. It answers with the configured
// responses and records every request the CLI sends.
type cov964GRPC struct {
	platformv1.IDevIDServiceClient

	err error

	genStatus     *platformv1.Status
	keyInfo       *platformv1.DeviceKeyInfo
	csrPEM        []byte
	installStatus *platformv1.Status
	cert          *platformv1.DeviceIdentityCertificate
	flushStatus   *platformv1.Status
	flushed       uint32
	attrs         *platformv1.TCGDeviceAttributes
	ldevid        *platformv1.CreateLDevIDResponse

	genIDevIDReq     *platformv1.GenerateIDevIDRequest
	genIAKReq        *platformv1.GenerateIAKRequest
	idevidCSRReq     *platformv1.CreateIDevIDCSRRequest
	iakCSRReq        *platformv1.CreateIAKCSRRequest
	installIDevIDReq *platformv1.InstallIDevIDCertificateRequest
	installIAKReq    *platformv1.InstallIAKCertificateRequest
	ldevidReq        *platformv1.CreateLDevIDRequest
}

// newCov964GRPC returns a daemon holding a provisioned key with a certificate.
func newCov964GRPC() *cov964GRPC {
	created := timestamppb.New(time.Unix(cov964Created, 0))
	cert := &platformv1.DeviceIdentityCertificate{
		Pem:                []byte("-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n"),
		SubjectCn:          "device-01",
		IssuerCn:           "platform-ca",
		SerialNumber:       "0a:0b",
		Fingerprint:        "sha256:feed",
		KeyAlgorithm:       "ECDSA",
		SignatureAlgorithm: "ECDSA-SHA384",
		KeySize:            384,
		IssuedAt:           created,
		ExpiresAt:          timestamppb.New(time.Unix(cov964Created+86400, 0)),
	}
	return &cov964GRPC{
		genStatus: &platformv1.Status{Success: true, Message: "generated"},
		keyInfo: &platformv1.DeviceKeyInfo{
			Handle:          0x81010001,
			Algorithm:       platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384,
			PublicKeyPem:    []byte("-----BEGIN PUBLIC KEY-----\nPUB\n-----END PUBLIC KEY-----\n"),
			CreatedAt:       created,
			HasCertificate:  true,
			CertificateInfo: cert,
		},
		csrPEM:        []byte("-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----\n"),
		installStatus: &platformv1.Status{Success: true, Message: "installed"},
		cert:          cert,
		flushStatus:   &platformv1.Status{Success: true, Message: "flushed"},
		flushed:       3,
		attrs: &platformv1.TCGDeviceAttributes{
			TpmManufacturer:      "IBM",
			TpmModel:             "SW TPM",
			TpmVersion:           "2.0",
			PlatformManufacturer: "Acme",
			PlatformModel:        "Edge-1",
			PlatformVersion:      "1.2",
			PlatformSerial:       "SN-42",
		},
		ldevid: &platformv1.CreateLDevIDResponse{
			Status:         &platformv1.Status{Success: true, Message: "issued"},
			CsrPem:         []byte("LDEVID-CSR\n"),
			CertificatePem: []byte("LDEVID-CERT\n"),
		},
	}
}

func (g *cov964GRPC) GenerateIDevID(_ context.Context, in *platformv1.GenerateIDevIDRequest, _ ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error) {
	g.genIDevIDReq = in
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.GenerateIDevIDResponse{Status: g.genStatus}, nil
}

func (g *cov964GRPC) GenerateIAK(_ context.Context, in *platformv1.GenerateIAKRequest, _ ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error) {
	g.genIAKReq = in
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.GenerateIAKResponse{Status: g.genStatus}, nil
}

func (g *cov964GRPC) GetIDevIDInfo(_ context.Context, _ *platformv1.GetIDevIDInfoRequest, _ ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.GetIDevIDInfoResponse{KeyInfo: g.keyInfo}, nil
}

func (g *cov964GRPC) GetIAKInfo(_ context.Context, _ *platformv1.GetIAKInfoRequest, _ ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.GetIAKInfoResponse{KeyInfo: g.keyInfo}, nil
}

func (g *cov964GRPC) CreateIDevIDCSR(_ context.Context, in *platformv1.CreateIDevIDCSRRequest, _ ...grpc.CallOption) (*platformv1.CreateIDevIDCSRResponse, error) {
	g.idevidCSRReq = in
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.CreateIDevIDCSRResponse{Status: &platformv1.Status{Success: true}, CsrPem: g.csrPEM}, nil
}

func (g *cov964GRPC) CreateIAKCSR(_ context.Context, in *platformv1.CreateIAKCSRRequest, _ ...grpc.CallOption) (*platformv1.CreateIAKCSRResponse, error) {
	g.iakCSRReq = in
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.CreateIAKCSRResponse{Status: &platformv1.Status{Success: true}, CsrPem: g.csrPEM}, nil
}

func (g *cov964GRPC) InstallIDevIDCertificate(_ context.Context, in *platformv1.InstallIDevIDCertificateRequest, _ ...grpc.CallOption) (*platformv1.InstallIDevIDCertificateResponse, error) {
	g.installIDevIDReq = in
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.InstallIDevIDCertificateResponse{Status: g.installStatus}, nil
}

func (g *cov964GRPC) InstallIAKCertificate(_ context.Context, in *platformv1.InstallIAKCertificateRequest, _ ...grpc.CallOption) (*platformv1.InstallIAKCertificateResponse, error) {
	g.installIAKReq = in
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.InstallIAKCertificateResponse{Status: g.installStatus}, nil
}

func (g *cov964GRPC) GetIDevIDCertificate(_ context.Context, _ *platformv1.GetIDevIDCertificateRequest, _ ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error) {
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.GetIDevIDCertificateResponse{Certificate: g.cert}, nil
}

func (g *cov964GRPC) GetIAKCertificate(_ context.Context, _ *platformv1.GetIAKCertificateRequest, _ ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.GetIAKCertificateResponse{Certificate: g.cert}, nil
}

func (g *cov964GRPC) FlushTransientContexts(_ context.Context, _ *platformv1.FlushTransientContextsRequest, _ ...grpc.CallOption) (*platformv1.FlushTransientContextsResponse, error) {
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.FlushTransientContextsResponse{Status: g.flushStatus, FlushedCount: g.flushed}, nil
}

func (g *cov964GRPC) GetDeviceAttributes(_ context.Context, _ *platformv1.GetDeviceAttributesRequest, _ ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error) {
	if g.err != nil {
		return nil, g.err
	}
	return &platformv1.GetDeviceAttributesResponse{Attributes: g.attrs}, nil
}

func (g *cov964GRPC) CreateLDevID(_ context.Context, in *platformv1.CreateLDevIDRequest, _ ...grpc.CallOption) (*platformv1.CreateLDevIDResponse, error) {
	g.ldevidReq = in
	if g.err != nil {
		return nil, g.err
	}
	return g.ldevid, nil
}

// cov964Base is an in-memory BaseCommandInterface: the printer writes to out
// and Close is counted.
type cov964Base struct {
	grpc   *cov964GRPC
	format cli.OutputFormat
	out    bytes.Buffer
	closed int
}

func newCov964Base(g *cov964GRPC, format cli.OutputFormat) *cov964Base {
	return &cov964Base{grpc: g, format: format}
}

func (b *cov964Base) Client() IDevIDClientProvider { return b }

func (b *cov964Base) IDevID() *idevidsvc.Client { return idevidsvc.NewClientFromGRPC(b.grpc) }

func (b *cov964Base) Printer() *cli.Printer {
	return cli.NewPrinterWithWriter(b.format, true, &b.out)
}

func (b *cov964Base) Context() context.Context { return context.Background() }

func (b *cov964Base) Close() error {
	b.closed++
	return nil
}

func (b *cov964Base) Flags() *cli.CommonFlags {
	return &cli.CommonFlags{OutputFormat: b.format, NoColor: true}
}

// decodeJSON decodes the printer output of a JSON run.
func (b *cov964Base) decodeJSON(t *testing.T) map[string]interface{} {
	t.Helper()
	var got map[string]interface{}
	if err := json.Unmarshal(b.out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, b.out.String())
	}
	return got
}

func cov964RequireClosed(t *testing.T, b *cov964Base) {
	t.Helper()
	if b.closed != 1 {
		t.Fatalf("Close called %d times, want 1", b.closed)
	}
}

func cov964RequireContains(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Fatalf("output missing %q:\n%s", w, out)
		}
	}
}

// cov964KeyRunners pairs the IDevID and IAK command bodies, which share a
// contract and differ only in the RPCs and typed errors.
type cov964KeyRunners struct {
	name       string
	keyType    string
	generate   func(BaseCommandInterface, string, bool) error
	info       func(BaseCommandInterface) error
	csr        func(BaseCommandInterface, string, string, string, string, string, string) error
	install    func(BaseCommandInterface, string) error
	cert       func(BaseCommandInterface) error
	genErr     func(error) bool
	infoErr    func(error) bool
	csrErr     func(error) bool
	installErr func(error) bool
	certErr    func(error) bool
	genReq     func(*cov964GRPC) (platformv1.DeviceKeyAlgorithm, bool, bool)
	csrReq     func(*cov964GRPC) *platformv1.CSRTemplate
	installReq func(*cov964GRPC) []byte
}

func cov964IsErr[T error](err error) bool {
	var target T
	return errors.As(err, &target)
}

func cov964Runners() []cov964KeyRunners {
	return []cov964KeyRunners{
		{
			name:       "IDevID",
			keyType:    "IDevID",
			generate:   runIDevIDGenerateWithClient,
			info:       runIDevIDInfoWithClient,
			csr:        runIDevIDCSRWithClient,
			install:    runIDevIDInstallWithClient,
			cert:       runIDevIDCertWithClient,
			genErr:     cov964IsErr[ErrGenerateIDevIDFailed],
			infoErr:    cov964IsErr[ErrGetIDevIDInfoFailed],
			csrErr:     cov964IsErr[ErrCreateIDevIDCSRFailed],
			installErr: cov964IsErr[ErrInstallIDevIDCertificateFailed],
			certErr:    cov964IsErr[ErrGetIDevIDCertificateFailed],
			genReq: func(g *cov964GRPC) (platformv1.DeviceKeyAlgorithm, bool, bool) {
				if g.genIDevIDReq == nil {
					return 0, false, false
				}
				return g.genIDevIDReq.GetConfig().GetAlgorithm(), g.genIDevIDReq.GetConfig().GetOverwrite(), true
			},
			csrReq: func(g *cov964GRPC) *platformv1.CSRTemplate { return g.idevidCSRReq.GetTemplate() },
			installReq: func(g *cov964GRPC) []byte {
				return g.installIDevIDReq.GetCertificatePem()
			},
		},
		{
			name:       "IAK",
			keyType:    "IAK",
			generate:   runIAKGenerateWithClient,
			info:       runIAKInfoWithClient,
			csr:        runIAKCSRWithClient,
			install:    runIAKInstallWithClient,
			cert:       runIAKCertWithClient,
			genErr:     cov964IsErr[ErrGenerateIAKFailed],
			infoErr:    cov964IsErr[ErrGetIAKInfoFailed],
			csrErr:     cov964IsErr[ErrCreateIAKCSRFailed],
			installErr: cov964IsErr[ErrInstallIAKCertificateFailed],
			certErr:    cov964IsErr[ErrGetIAKCertificateFailed],
			genReq: func(g *cov964GRPC) (platformv1.DeviceKeyAlgorithm, bool, bool) {
				if g.genIAKReq == nil {
					return 0, false, false
				}
				return g.genIAKReq.GetConfig().GetAlgorithm(), g.genIAKReq.GetConfig().GetOverwrite(), true
			},
			csrReq: func(g *cov964GRPC) *platformv1.CSRTemplate { return g.iakCSRReq.GetTemplate() },
			installReq: func(g *cov964GRPC) []byte {
				return g.installIAKReq.GetCertificatePem()
			},
		},
	}
}

func TestCov964GenerateKey(t *testing.T) {
	for _, r := range cov964Runners() {
		t.Run(r.name+"/JSON sends algorithm and overwrite", func(t *testing.T) {
			g := newCov964GRPC()
			b := newCov964Base(g, cli.OutputFormatJSON)
			if err := r.generate(b, "ecdsa-p384", true); err != nil {
				t.Fatalf("generate: %v", err)
			}
			alg, overwrite, sent := r.genReq(g)
			if !sent {
				t.Fatal("no generate request sent")
			}
			if alg != platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384 || !overwrite {
				t.Fatalf("request algorithm=%v overwrite=%v, want ECDSA_P384 true", alg, overwrite)
			}
			got := b.decodeJSON(t)
			if got["algorithm"] != "ecdsa-p384" || got["handle"] != "0x81010001" {
				t.Fatalf("algorithm/handle = %v/%v", got["algorithm"], got["handle"])
			}
			if got["created_at"] != float64(cov964Created) {
				t.Fatalf("created_at = %v, want %d", got["created_at"], cov964Created)
			}
			if !strings.Contains(got["public_key_pem"].(string), "PUB") {
				t.Fatalf("public_key_pem = %v", got["public_key_pem"])
			}
			cov964RequireClosed(t, b)
		})

		t.Run(r.name+"/table reports success", func(t *testing.T) {
			b := newCov964Base(newCov964GRPC(), cli.OutputFormatTable)
			if err := r.generate(b, "RSA-2048", false); err != nil {
				t.Fatalf("generate: %v", err)
			}
			cov964RequireContains(t, b.out.String(), "[SUCCESS] "+r.keyType+" key generated successfully", "Algorithm", "RSA-2048")
		})

		t.Run(r.name+"/daemon refusal is typed", func(t *testing.T) {
			g := newCov964GRPC()
			g.genStatus = &platformv1.Status{Success: false, Message: "key exists at handle"}
			b := newCov964Base(g, cli.OutputFormatJSON)
			err := r.generate(b, "P256", false)
			if !r.genErr(err) || !strings.Contains(err.Error(), "key exists at handle") {
				t.Fatalf("err = %v, want typed generate failure carrying the daemon message", err)
			}
			cov964RequireClosed(t, b)
		})

		t.Run(r.name+"/invalid algorithm sends nothing", func(t *testing.T) {
			g := newCov964GRPC()
			b := newCov964Base(g, cli.OutputFormatJSON)
			err := r.generate(b, "DSA-1024", false)
			var invalid ErrInvalidAlgorithm
			if !errors.As(err, &invalid) || invalid.Algorithm != "DSA-1024" {
				t.Fatalf("err = %v, want ErrInvalidAlgorithm{DSA-1024}", err)
			}
			if _, _, sent := r.genReq(g); sent {
				t.Fatal("generate request sent for an invalid algorithm")
			}
			cov964RequireClosed(t, b)
		})
	}
}

func TestCov964KeyInfo(t *testing.T) {
	for _, r := range cov964Runners() {
		t.Run(r.name+"/JSON includes certificate info", func(t *testing.T) {
			b := newCov964Base(newCov964GRPC(), cli.OutputFormatJSON)
			if err := r.info(b); err != nil {
				t.Fatalf("info: %v", err)
			}
			got := b.decodeJSON(t)
			if got["exists"] != true || got["has_certificate"] != true || got["handle"] != "0x81010001" {
				t.Fatalf("exists/has_certificate/handle = %v/%v/%v", got["exists"], got["has_certificate"], got["handle"])
			}
			certInfo, ok := got["certificate_info"].(map[string]interface{})
			if !ok {
				t.Fatalf("certificate_info missing: %v", got)
			}
			if certInfo["subject_cn"] != "device-01" || certInfo["issuer_cn"] != "platform-ca" {
				t.Fatalf("certificate_info = %v", certInfo)
			}
			if certInfo["issued_at"] != float64(cov964Created) || certInfo["expires_at"] != float64(cov964Created+86400) {
				t.Fatalf("issued_at/expires_at = %v/%v", certInfo["issued_at"], certInfo["expires_at"])
			}
			cov964RequireClosed(t, b)
		})

		t.Run(r.name+"/table prints key and certificate", func(t *testing.T) {
			b := newCov964Base(newCov964GRPC(), cli.OutputFormatTable)
			if err := r.info(b); err != nil {
				t.Fatalf("info: %v", err)
			}
			cov964RequireContains(t, b.out.String(),
				"Key Type", r.keyType, "0x81010001", "2023-11-14T22:13:20Z",
				"Subject CN", "device-01", "Fingerprint", "sha256:feed", "Expires At", "2023-11-15T22:13:20Z")
		})

		t.Run(r.name+"/missing key is typed", func(t *testing.T) {
			g := newCov964GRPC()
			g.keyInfo = nil
			b := newCov964Base(g, cli.OutputFormatJSON)
			if err := r.info(b); !r.infoErr(err) {
				t.Fatalf("err = %v, want typed info failure", err)
			}
			cov964RequireClosed(t, b)
		})
	}
}

func TestCov964CSR(t *testing.T) {
	for _, r := range cov964Runners() {
		t.Run(r.name+"/JSON sends the subject template", func(t *testing.T) {
			g := newCov964GRPC()
			b := newCov964Base(g, cli.OutputFormatJSON)
			if err := r.csr(b, "device-01", "Acme", "US", "CA", "Berkeley", "Edge"); err != nil {
				t.Fatalf("csr: %v", err)
			}
			tmpl := r.csrReq(g)
			if tmpl.GetCommonName() != "device-01" || tmpl.GetOrganization() != "Acme" ||
				tmpl.GetCountry() != "US" || tmpl.GetProvince() != "CA" ||
				tmpl.GetLocality() != "Berkeley" || tmpl.GetOrganizationalUnit() != "Edge" {
				t.Fatalf("template = %v", tmpl)
			}
			var got struct {
				CSRPEM []byte `json:"csr_pem"`
			}
			if err := json.Unmarshal(b.out.Bytes(), &got); err != nil {
				t.Fatalf("output is not JSON: %v", err)
			}
			if !bytes.Equal(got.CSRPEM, g.csrPEM) {
				t.Fatalf("csr_pem = %q, want %q", got.CSRPEM, g.csrPEM)
			}
			cov964RequireClosed(t, b)
		})

		t.Run(r.name+"/table reports success", func(t *testing.T) {
			b := newCov964Base(newCov964GRPC(), cli.OutputFormatTable)
			if err := r.csr(b, "device-01", "", "", "", "", ""); err != nil {
				t.Fatalf("csr: %v", err)
			}
			cov964RequireContains(t, b.out.String(), "[SUCCESS]")
		})

		t.Run(r.name+"/daemon failure is typed", func(t *testing.T) {
			g := newCov964GRPC()
			g.err = cov964RPCError{Op: "csr"}
			b := newCov964Base(g, cli.OutputFormatJSON)
			err := r.csr(b, "device-01", "", "", "", "", "")
			if !r.csrErr(err) || !strings.Contains(err.Error(), "rpc csr unavailable") {
				t.Fatalf("err = %v, want typed CSR failure", err)
			}
			cov964RequireClosed(t, b)
		})
	}
}

func TestCov964InstallCertificate(t *testing.T) {
	certBody := []byte("-----BEGIN CERTIFICATE-----\nINSTALL\n-----END CERTIFICATE-----\n")
	writeCert := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "device.pem")
		if err := os.WriteFile(path, certBody, 0o600); err != nil {
			t.Fatalf("write cert: %v", err)
		}
		return path
	}

	for _, r := range cov964Runners() {
		t.Run(r.name+"/JSON sends the file contents", func(t *testing.T) {
			g := newCov964GRPC()
			b := newCov964Base(g, cli.OutputFormatJSON)
			if err := r.install(b, writeCert(t)); err != nil {
				t.Fatalf("install: %v", err)
			}
			if !bytes.Equal(r.installReq(g), certBody) {
				t.Fatalf("certificate_pem sent = %q", r.installReq(g))
			}
			got := b.decodeJSON(t)
			if got["installed"] != true || got["message"] != "installed" {
				t.Fatalf("output = %v", got)
			}
			cov964RequireClosed(t, b)
		})

		t.Run(r.name+"/table reports success", func(t *testing.T) {
			b := newCov964Base(newCov964GRPC(), cli.OutputFormatTable)
			if err := r.install(b, writeCert(t)); err != nil {
				t.Fatalf("install: %v", err)
			}
			cov964RequireContains(t, b.out.String(), "[SUCCESS] "+r.keyType+" certificate installed successfully")
		})

		t.Run(r.name+"/table reports a refusal with its message", func(t *testing.T) {
			g := newCov964GRPC()
			g.installStatus = &platformv1.Status{Success: false, Message: "chain does not verify"}
			b := newCov964Base(g, cli.OutputFormatTable)
			if err := r.install(b, writeCert(t)); err != nil {
				t.Fatalf("install: %v", err)
			}
			cov964RequireContains(t, b.out.String(), "[ERROR] Failed to install certificate: chain does not verify")
		})

		t.Run(r.name+"/table reports a refusal without a message", func(t *testing.T) {
			g := newCov964GRPC()
			g.installStatus = &platformv1.Status{Success: false}
			b := newCov964Base(g, cli.OutputFormatTable)
			if err := r.install(b, writeCert(t)); err != nil {
				t.Fatalf("install: %v", err)
			}
			cov964RequireContains(t, b.out.String(), "[ERROR] Failed to install certificate: unknown error")
		})

		t.Run(r.name+"/unreadable file sends nothing", func(t *testing.T) {
			g := newCov964GRPC()
			b := newCov964Base(g, cli.OutputFormatJSON)
			err := r.install(b, filepath.Join(t.TempDir(), "absent.pem"))
			if !r.installErr(err) || !strings.Contains(err.Error(), "failed to read certificate file") {
				t.Fatalf("err = %v, want typed read failure", err)
			}
			if g.installIDevIDReq != nil || g.installIAKReq != nil {
				t.Fatal("install request sent for an unreadable file")
			}
			cov964RequireClosed(t, b)
		})

		t.Run(r.name+"/daemon failure is typed", func(t *testing.T) {
			g := newCov964GRPC()
			g.err = cov964RPCError{Op: "install"}
			b := newCov964Base(g, cli.OutputFormatJSON)
			if err := r.install(b, writeCert(t)); !r.installErr(err) {
				t.Fatalf("err = %v, want typed install failure", err)
			}
		})
	}
}

func TestCov964GetCertificate(t *testing.T) {
	for _, r := range cov964Runners() {
		t.Run(r.name+"/JSON carries validity", func(t *testing.T) {
			b := newCov964Base(newCov964GRPC(), cli.OutputFormatJSON)
			if err := r.cert(b); err != nil {
				t.Fatalf("cert: %v", err)
			}
			got := b.decodeJSON(t)
			if got["subject"] != "device-01" || got["issuer"] != "platform-ca" || got["serial_number"] != "0a:0b" {
				t.Fatalf("output = %v", got)
			}
			if got["not_before"] != float64(cov964Created) || got["not_after"] != float64(cov964Created+86400) {
				t.Fatalf("not_before/not_after = %v/%v", got["not_before"], got["not_after"])
			}
			cov964RequireClosed(t, b)
		})

		t.Run(r.name+"/table prints certificate details", func(t *testing.T) {
			b := newCov964Base(newCov964GRPC(), cli.OutputFormatTable)
			if err := r.cert(b); err != nil {
				t.Fatalf("cert: %v", err)
			}
			cov964RequireContains(t, b.out.String(),
				"Key Type", r.keyType, "Signature Algorithm", "ECDSA-SHA384", "Issued At", "2023-11-14T22:13:20Z")
		})

		t.Run(r.name+"/missing certificate is typed", func(t *testing.T) {
			g := newCov964GRPC()
			g.cert = nil
			b := newCov964Base(g, cli.OutputFormatJSON)
			if err := r.cert(b); !r.certErr(err) {
				t.Fatalf("err = %v, want typed certificate failure", err)
			}
			cov964RequireClosed(t, b)
		})
	}
}

func TestCov964BuildCertificateOutputOmitsZeroValidity(t *testing.T) {
	got := buildCertificateOutput(&idevidsvc.DeviceIdentityCertificate{PEM: "P", SubjectCN: "s"})
	if _, ok := got["not_before"]; ok {
		t.Fatal("not_before present for a zero timestamp")
	}
	if _, ok := got["not_after"]; ok {
		t.Fatal("not_after present for a zero timestamp")
	}
	if got["certificate_pem"] != "P" || got["subject"] != "s" {
		t.Fatalf("output = %v", got)
	}
}

func TestCov964BuildGenerateKeyOutputWithoutInfo(t *testing.T) {
	got := buildGenerateKeyOutput(nil, "RSA-3072")
	if len(got) != 1 || got["algorithm"] != "RSA-3072" {
		t.Fatalf("output = %v, want only the algorithm", got)
	}
}

func TestCov964FormatTimestampSeconds(t *testing.T) {
	if got := formatTimestampSeconds(0); got != "N/A" {
		t.Fatalf("formatTimestampSeconds(0) = %q, want N/A", got)
	}
	if got := formatTimestampSeconds(cov964Created); got != "2023-11-14T22:13:20Z" {
		t.Fatalf("formatTimestampSeconds = %q", got)
	}
}

func TestCov964Flush(t *testing.T) {
	t.Run("JSON reports the count", func(t *testing.T) {
		b := newCov964Base(newCov964GRPC(), cli.OutputFormatJSON)
		if err := runFlushWithClient(b); err != nil {
			t.Fatalf("flush: %v", err)
		}
		got := b.decodeJSON(t)
		if got["flushed_count"] != float64(3) || got["message"] != "flushed" {
			t.Fatalf("output = %v", got)
		}
		cov964RequireClosed(t, b)
	})

	t.Run("table reports the count", func(t *testing.T) {
		b := newCov964Base(newCov964GRPC(), cli.OutputFormatTable)
		if err := runFlushWithClient(b); err != nil {
			t.Fatalf("flush: %v", err)
		}
		cov964RequireContains(t, b.out.String(), "Flushed 3 transient TPM contexts")
	})

	t.Run("daemon failure is typed", func(t *testing.T) {
		g := newCov964GRPC()
		g.err = cov964RPCError{Op: "flush"}
		b := newCov964Base(g, cli.OutputFormatJSON)
		var target ErrFlushFailed
		if err := runFlushWithClient(b); !errors.As(err, &target) {
			t.Fatalf("err = %v, want ErrFlushFailed", err)
		}
		cov964RequireClosed(t, b)
	})
}

func TestCov964DeviceAttributes(t *testing.T) {
	t.Run("JSON reports the TPM identity", func(t *testing.T) {
		b := newCov964Base(newCov964GRPC(), cli.OutputFormatJSON)
		if err := runDeviceAttributesWithClient(b); err != nil {
			t.Fatalf("attributes: %v", err)
		}
		got := b.decodeJSON(t)
		if got["manufacturer"] != "IBM" || got["model"] != "SW TPM" || got["version"] != "2.0" {
			t.Fatalf("output = %v", got)
		}
		cov964RequireClosed(t, b)
	})

	t.Run("table reports TPM and platform", func(t *testing.T) {
		b := newCov964Base(newCov964GRPC(), cli.OutputFormatTable)
		if err := runDeviceAttributesWithClient(b); err != nil {
			t.Fatalf("attributes: %v", err)
		}
		cov964RequireContains(t, b.out.String(), "TPM Manufacturer", "IBM", "Platform Serial", "SN-42")
	})

	t.Run("missing attributes are typed", func(t *testing.T) {
		g := newCov964GRPC()
		g.attrs = nil
		b := newCov964Base(g, cli.OutputFormatJSON)
		var target ErrGetDeviceAttributesFailed
		if err := runDeviceAttributesWithClient(b); !errors.As(err, &target) {
			t.Fatalf("err = %v, want ErrGetDeviceAttributesFailed", err)
		}
		cov964RequireClosed(t, b)
	})
}

func TestCov964LDevIDCreate(t *testing.T) {
	t.Run("JSON sends the request and writes artifacts", func(t *testing.T) {
		g := newCov964GRPC()
		b := newCov964Base(g, cli.OutputFormatJSON)
		out := filepath.Join(t.TempDir(), "ldevid.pem")
		f := &ldevidCreateFlags{
			commonName:   "device-01",
			state:        "CA",
			algorithm:    "ECDSA-P384",
			handle:       "0x81010102",
			profile:      "ldevid",
			validityDays: 90,
			overwrite:    true,
			out:          out,
		}
		if err := runLDevIDCreateWithClient(b, f); err != nil {
			t.Fatalf("create: %v", err)
		}
		req := g.ldevidReq
		if req.GetHandle() != 0x81010102 || req.GetProfile() != "ldevid" || req.GetValidityDays() != 90 || !req.GetOverwrite() {
			t.Fatalf("request = %v", req)
		}
		if req.GetAlgorithm() != platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384 {
			t.Fatalf("algorithm = %v", req.GetAlgorithm())
		}
		if req.GetTemplate().GetCommonName() != "device-01" || req.GetTemplate().GetProvince() != "CA" {
			t.Fatalf("template = %v", req.GetTemplate())
		}
		cert, err := os.ReadFile(out)
		if err != nil || string(cert) != "LDEVID-CERT\n" {
			t.Fatalf("certificate file = %q, %v", cert, err)
		}
		csr, err := os.ReadFile(out + ".csr")
		if err != nil || string(csr) != "LDEVID-CSR\n" {
			t.Fatalf("CSR file = %q, %v", csr, err)
		}
		got := b.decodeJSON(t)
		if got["success"] != true || got["status"] != "issued" || got["certificate_pem"] != "LDEVID-CERT\n" {
			t.Fatalf("output = %v", got)
		}
		cov964RequireClosed(t, b)
	})

	t.Run("table names the written files", func(t *testing.T) {
		b := newCov964Base(newCov964GRPC(), cli.OutputFormatTable)
		out := filepath.Join(t.TempDir(), "ldevid.pem")
		if err := runLDevIDCreateWithClient(b, &ldevidCreateFlags{out: out}); err != nil {
			t.Fatalf("create: %v", err)
		}
		cov964RequireContains(t, b.out.String(), "[SUCCESS] LDevID certificate issued successfully", out, out+".csr")
	})

	t.Run("table without out prints only success", func(t *testing.T) {
		g := newCov964GRPC()
		b := newCov964Base(g, cli.OutputFormatTable)
		if err := runLDevIDCreateWithClient(b, &ldevidCreateFlags{}); err != nil {
			t.Fatalf("create: %v", err)
		}
		if g.ldevidReq.GetTemplate() != nil {
			t.Fatalf("template sent without subject flags: %v", g.ldevidReq.GetTemplate())
		}
		cov964RequireContains(t, b.out.String(), "[SUCCESS] LDevID certificate issued successfully")
	})

	t.Run("invalid handle sends nothing", func(t *testing.T) {
		g := newCov964GRPC()
		b := newCov964Base(g, cli.OutputFormatJSON)
		err := runLDevIDCreateWithClient(b, &ldevidCreateFlags{handle: "not-a-handle"})
		var target ErrInvalidTPMHandle
		if !errors.As(err, &target) || target.Handle != "not-a-handle" {
			t.Fatalf("err = %v, want ErrInvalidTPMHandle", err)
		}
		if g.ldevidReq != nil {
			t.Fatal("request sent for an invalid handle")
		}
		cov964RequireClosed(t, b)
	})

	t.Run("invalid algorithm sends nothing", func(t *testing.T) {
		g := newCov964GRPC()
		b := newCov964Base(g, cli.OutputFormatJSON)
		var target ErrInvalidAlgorithm
		if err := runLDevIDCreateWithClient(b, &ldevidCreateFlags{algorithm: "DSA"}); !errors.As(err, &target) {
			t.Fatalf("err = %v, want ErrInvalidAlgorithm", err)
		}
		if g.ldevidReq != nil {
			t.Fatal("request sent for an invalid algorithm")
		}
	})

	t.Run("daemon failure is typed", func(t *testing.T) {
		g := newCov964GRPC()
		g.err = cov964RPCError{Op: "ldevid"}
		b := newCov964Base(g, cli.OutputFormatJSON)
		var target ErrCreateLDevIDFailed
		err := runLDevIDCreateWithClient(b, &ldevidCreateFlags{})
		if !errors.As(err, &target) || !strings.Contains(err.Error(), "rpc ldevid unavailable") {
			t.Fatalf("err = %v, want ErrCreateLDevIDFailed", err)
		}
	})

	for _, format := range []cli.OutputFormat{cli.OutputFormatJSON, cli.OutputFormatTable} {
		t.Run(string(format)+" artifact write failure is typed", func(t *testing.T) {
			b := newCov964Base(newCov964GRPC(), format)
			out := filepath.Join(t.TempDir(), "missing-dir", "ldevid.pem")
			var target ErrCreateLDevIDFailed
			err := runLDevIDCreateWithClient(b, &ldevidCreateFlags{out: out})
			if !errors.As(err, &target) || !strings.Contains(err.Error(), "failed to write certificate") {
				t.Fatalf("err = %v, want ErrCreateLDevIDFailed write failure", err)
			}
		})
	}
}

// TestCov964InvalidOutputFormat checks that every daemon-backed command
// rejects an unknown output format after a successful call, and still closes.
func TestCov964InvalidOutputFormat(t *testing.T) {
	certPath := filepath.Join(t.TempDir(), "device.pem")
	if err := os.WriteFile(certPath, []byte("CERT"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	runs := map[string]func(BaseCommandInterface) error{
		"idevid generate": func(b BaseCommandInterface) error { return runIDevIDGenerateWithClient(b, "P256", false) },
		"iak generate":    func(b BaseCommandInterface) error { return runIAKGenerateWithClient(b, "P256", false) },
		"idevid info":     runIDevIDInfoWithClient,
		"iak info":        runIAKInfoWithClient,
		"idevid csr": func(b BaseCommandInterface) error {
			return runIDevIDCSRWithClient(b, "cn", "", "", "", "", "")
		},
		"iak csr": func(b BaseCommandInterface) error {
			return runIAKCSRWithClient(b, "cn", "", "", "", "", "")
		},
		"idevid install": func(b BaseCommandInterface) error { return runIDevIDInstallWithClient(b, certPath) },
		"iak install":    func(b BaseCommandInterface) error { return runIAKInstallWithClient(b, certPath) },
		"idevid cert":    runIDevIDCertWithClient,
		"iak cert":       runIAKCertWithClient,
		"flush":          runFlushWithClient,
		"attributes":     runDeviceAttributesWithClient,
		"ldevid create": func(b BaseCommandInterface) error {
			return runLDevIDCreateWithClient(b, &ldevidCreateFlags{})
		},
	}
	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			b := newCov964Base(newCov964GRPC(), cli.OutputFormat("xml"))
			var target cli.ErrInvalidOutputFormat
			if err := run(b); !errors.As(err, &target) || target.Format != "xml" {
				t.Fatalf("err = %v, want ErrInvalidOutputFormat{xml}", err)
			}
			cov964RequireClosed(t, b)
		})
	}
}

func TestCov964DaemonFailuresAreTyped(t *testing.T) {
	for _, r := range cov964Runners() {
		t.Run(r.name+"/generate", func(t *testing.T) {
			g := newCov964GRPC()
			g.err = cov964RPCError{Op: "generate"}
			if err := r.generate(newCov964Base(g, cli.OutputFormatJSON), "P256", false); !r.genErr(err) {
				t.Fatalf("err = %v, want typed generate failure", err)
			}
		})
		t.Run(r.name+"/info", func(t *testing.T) {
			g := newCov964GRPC()
			g.err = cov964RPCError{Op: "info"}
			if err := r.info(newCov964Base(g, cli.OutputFormatJSON)); !r.infoErr(err) {
				t.Fatalf("err = %v, want typed info failure", err)
			}
		})
		t.Run(r.name+"/cert", func(t *testing.T) {
			g := newCov964GRPC()
			g.err = cov964RPCError{Op: "cert"}
			if err := r.cert(newCov964Base(g, cli.OutputFormatJSON)); !r.certErr(err) {
				t.Fatalf("err = %v, want typed certificate failure", err)
			}
		})
	}
}

func TestCov964ErrorMessages(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"certify failed":     {ErrCertifyFailed{Handle: 0x81000001, Reason: "denied"}, "failed to certify key 0x81000001: denied"},
		"certify nonce":      {ErrInvalidCertifyNonce{Nonce: "zz"}, `invalid certify nonce "zz": expected hex`},
		"ldevid failed":      {ErrCreateLDevIDFailed{Reason: "no IDevID"}, "failed to create LDevID: no IDevID"},
		"invalid tpm handle": {ErrInvalidTPMHandle{Handle: "x"}, `invalid TPM handle "x": expected hex (0x...) or decimal uint32`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}
