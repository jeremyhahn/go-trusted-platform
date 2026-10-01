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

package device

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newCLITestEKCertPEM generates a self-signed ECDSA certificate PEM for
// the --ek-cert flag tests.
func newCLITestEKCertPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestResolveEKCertPEM verifies the --ek-cert flag resolution: empty,
// inline PEM, file path, and the malformed error paths.
func TestResolveEKCertPEM(t *testing.T) {
	certPEM := newCLITestEKCertPEM(t)

	t.Run("empty resolves to no prestage", func(t *testing.T) {
		resolved, err := resolveEKCertPEM("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved != "" {
			t.Fatalf("resolved = %q, want empty", resolved)
		}
	})

	t.Run("inline PEM is used verbatim", func(t *testing.T) {
		resolved, err := resolveEKCertPEM(certPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved != certPEM {
			t.Fatal("inline PEM must be returned verbatim")
		}
	})

	t.Run("file path is read and validated", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ek-cert.pem")
		if err := os.WriteFile(path, []byte(certPEM), 0o600); err != nil {
			t.Fatalf("write cert: %v", err)
		}
		resolved, err := resolveEKCertPEM(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved != certPEM {
			t.Fatal("file PEM must round-trip")
		}
	})

	t.Run("missing file is a typed read error", func(t *testing.T) {
		_, err := resolveEKCertPEM(filepath.Join(t.TempDir(), "missing.pem"))
		var readErr ErrProfileEKCertReadFailed
		if !errors.As(err, &readErr) {
			t.Fatalf("err = %v, want ErrProfileEKCertReadFailed", err)
		}
	})

	t.Run("file without PEM is a typed validation error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bogus.pem")
		if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		_, err := resolveEKCertPEM(path)
		var invalid ErrProfileEKCertInvalid
		if !errors.As(err, &invalid) {
			t.Fatalf("err = %v, want ErrProfileEKCertInvalid", err)
		}
	})

	t.Run("inline PEM with bad DER is rejected", func(t *testing.T) {
		bogus := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))
		_, err := resolveEKCertPEM(bogus)
		var invalid ErrProfileEKCertInvalid
		if !errors.As(err, &invalid) {
			t.Fatalf("err = %v, want ErrProfileEKCertInvalid", err)
		}
	})
}

// TestLoadProfileConfig verifies the --config-file flag: YAML and JSON
// inputs convert to JSON bytes, and the error paths are typed.
func TestLoadProfileConfig(t *testing.T) {
	t.Run("empty path resolves to nil", func(t *testing.T) {
		configJSON, err := loadProfileConfig("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if configJSON != nil {
			t.Fatal("expected nil config for empty path")
		}
	})

	t.Run("yaml converts to JSON bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte("hostname: lab-node-2\nsecure-boot:\n  enabled: true\n"), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		configJSON, err := loadProfileConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(configJSON, &decoded); err != nil {
			t.Fatalf("config is not JSON: %v", err)
		}
		if decoded["hostname"] != "lab-node-2" {
			t.Fatalf("decoded = %v", decoded)
		}
	})

	t.Run("missing file is a typed read error", func(t *testing.T) {
		_, err := loadProfileConfig(filepath.Join(t.TempDir(), "missing.yaml"))
		var readErr ErrProfileConfigReadFailed
		if !errors.As(err, &readErr) {
			t.Fatalf("err = %v, want ErrProfileConfigReadFailed", err)
		}
	})

	t.Run("malformed yaml is a typed parse error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(path, []byte(":\n\t- ["), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		_, err := loadProfileConfig(path)
		var parseErr ErrProfileConfigParseFailed
		if !errors.As(err, &parseErr) {
			t.Fatalf("err = %v, want ErrProfileConfigParseFailed", err)
		}
	})
}

// TestResolveProfileRole verifies role label mapping and the invalid-role
// error path.
func TestResolveProfileRole(t *testing.T) {
	tests := []struct {
		role    string
		want    platformv1.DeviceRole
		wantErr bool
	}{
		{role: "", want: platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED},
		{role: "server", want: platformv1.DeviceRole_DEVICE_ROLE_SERVER},
		{role: "gateway", want: platformv1.DeviceRole_DEVICE_ROLE_GATEWAY},
		{role: "load-balancer", want: platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER},
		{role: "control-plane", want: platformv1.DeviceRole_DEVICE_ROLE_CONTROL_PLANE},
		{role: "worker", want: platformv1.DeviceRole_DEVICE_ROLE_WORKER},
		{role: "bogus", wantErr: true},
	}
	for _, tc := range tests {
		t.Run("role "+tc.role, func(t *testing.T) {
			got, err := resolveProfileRole(tc.role)
			if tc.wantErr {
				var invalid ErrProfileInvalidRole
				if !errors.As(err, &invalid) {
					t.Fatalf("err = %v, want ErrProfileInvalidRole", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("role = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBuildProfileOutput verifies the output map: the uint64 ID is a
// decimal string and the prestage fields surface when set.
func TestBuildProfileOutput(t *testing.T) {
	certPEM := newCLITestEKCertPEM(t)
	output := buildProfileOutput(&platformv1.DeviceProfile{
		Id:         18446744073709551615,
		Name:       "lab-node-2",
		Role:       platformv1.DeviceRole_DEVICE_ROLE_SERVER,
		EkSerial:   "EK-CLI-1",
		MacAddress: "aa:bb:cc:dd:ee:51",
		EkCert:     certPEM,
		Config:     []byte(`{"hostname":"lab-node-2"}`),
	})

	if output["id"] != "18446744073709551615" {
		t.Fatalf("id = %v, want max-uint64 decimal string", output["id"])
	}
	if output["ek_serial"] != "EK-CLI-1" || output["mac_address"] != "aa:bb:cc:dd:ee:51" {
		t.Fatalf("identity fields = %v", output)
	}
	if output["ek_cert"] != certPEM {
		t.Fatal("ek_cert missing from output")
	}
	if output["role"] != "server" {
		t.Fatalf("role = %v", output["role"])
	}
}

// TestNewProfileCommand verifies the command tree exposes create and
// update with the prestage flags registered.
func TestNewProfileCommand(t *testing.T) {
	cmd := newProfileCommand(nil)
	subs := map[string]bool{}
	for _, sub := range cmd.Commands() {
		subs[sub.Name()] = true
	}
	if !subs["create"] || !subs["update"] || !subs["assign"] || !subs["unassign"] || !subs["get"] || !subs["list"] {
		t.Fatalf("profile command must expose get, list, create, update, assign, and unassign, got %v", subs)
	}

	for _, sub := range cmd.Commands() {
		if sub.Name() != "create" && sub.Name() != "update" {
			continue
		}
		for _, flag := range []string{"name", "model", "role", "zone", "ek-serial", "mac", "ek-cert", "config-file", "tls-server-name"} {
			if sub.Flags().Lookup(flag) == nil {
				t.Errorf("%s missing flag --%s", sub.Name(), flag)
			}
		}
	}
}

// TestBuildProfileOutput_TLSServerNameAndBaseline pins that the JSON/YAML
// output reports the collector server name and the read-only baseline the
// server returns (source, hex digests by register, RFC3339 recording time,
// seeding device as a decimal string), and omits both when absent.
func TestBuildProfileOutput_TLSServerNameAndBaseline(t *testing.T) {
	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	output := buildProfileOutput(&platformv1.DeviceProfile{
		Id:            7,
		Name:          "compute",
		TlsServerName: "compute.trusted-platform.internal",
		PcrBaseline: &platformv1.PCRBaseline{
			Values:               map[uint32][]byte{0: {0xaa, 0xbb}, 7: {0x01}},
			Source:               "tofu",
			RecordedAt:           timestamppb.New(recorded),
			RecordedFromDeviceId: 9007199254740993,
		},
	})
	if output["tls_server_name"] != "compute.trusted-platform.internal" {
		t.Fatalf("tls_server_name = %v", output["tls_server_name"])
	}
	baseline, ok := output["pcr_baseline"].(map[string]interface{})
	if !ok {
		t.Fatalf("pcr_baseline missing: %v", output)
	}
	if baseline["source"] != "tofu" || baseline["recorded_at"] != "2026-09-01T12:00:00Z" || baseline["recorded_from_device_id"] != "9007199254740993" {
		t.Fatalf("baseline = %v", baseline)
	}
	if values := baseline["values"].(map[string]string); values["0"] != "aabb" || values["7"] != "01" {
		t.Fatalf("values = %v", values)
	}

	bare := buildProfileOutput(&platformv1.DeviceProfile{Id: 8, Name: "q"})
	if _, present := bare["tls_server_name"]; present {
		t.Fatal("an absent tls_server_name must be omitted")
	}
	if _, present := bare["pcr_baseline"]; present {
		t.Fatal("an absent baseline must be omitted")
	}
	if profileBaselineOutput(nil) != nil {
		t.Fatal("nil baseline must render as nil")
	}
	if got := profileBaselineSummary(&platformv1.PCRBaseline{Source: "signed", Values: map[uint32][]byte{0: {1}}}); got != "signed (1 registers)" {
		t.Fatalf("summary without a timestamp = %q", got)
	}
}

// TestApplyProfileUpdateFlags_SetAndPreserve pins the update merge: a
// supplied --tls-server-name replaces the fetched value, an unset one leaves
// it (and the read-only baseline the server returned) untouched so the
// full-replace UpdateProfile that follows cannot erase them.
func TestApplyProfileUpdateFlags_SetAndPreserve(t *testing.T) {
	fetched := func() *platformv1.DeviceProfile {
		return &platformv1.DeviceProfile{
			Id: 7, Name: "compute", Model: "X10SDV", Zone: "control-plane",
			TlsServerName: "compute.trusted-platform.internal",
			PcrBaseline:   &platformv1.PCRBaseline{Source: "tofu", Values: map[uint32][]byte{7: {0xbb}}},
		}
	}

	profile := fetched()
	if err := applyProfileUpdateFlags(profile, &profileFlags{model: "X10SDV-TP8F"}, "", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.GetModel() != "X10SDV-TP8F" {
		t.Fatalf("model not applied: %q", profile.GetModel())
	}
	if profile.GetTlsServerName() != "compute.trusted-platform.internal" {
		t.Fatal("an update without --tls-server-name must not clear the fetched value")
	}
	if profile.GetPcrBaseline() == nil || profile.GetPcrBaseline().GetSource() != "tofu" {
		t.Fatal("the read-only baseline the server returned must travel back untouched")
	}
	if profile.GetName() != "compute" || profile.GetZone() != "control-plane" {
		t.Fatal("unset flags must leave their fields untouched")
	}

	profile = fetched()
	if err := applyProfileUpdateFlags(profile, &profileFlags{tlsServerName: "gw.trusted-platform.internal"}, "", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.GetTlsServerName() != "gw.trusted-platform.internal" {
		t.Fatalf("--tls-server-name not applied: %q", profile.GetTlsServerName())
	}
}

// TestApplyProfileUpdateFlags_InvalidRole proves a bad --role is rejected
// before anything is written, with the typed CLI error.
func TestApplyProfileUpdateFlags_InvalidRole(t *testing.T) {
	profile := &platformv1.DeviceProfile{Id: 7, Name: "compute", TlsServerName: "compute.trusted-platform.internal"}
	err := applyProfileUpdateFlags(profile, &profileFlags{role: "hypervisor", tlsServerName: "x"}, "", nil)
	var invalid ErrProfileInvalidRole
	if !errors.As(err, &invalid) || invalid.Role != "hypervisor" {
		t.Fatalf("expected ErrProfileInvalidRole, got %v", err)
	}
	if profile.GetTlsServerName() != "compute.trusted-platform.internal" {
		t.Fatal("a rejected update must not have mutated the profile before the error")
	}
}

// TestProfileListCommand_Flags pins the list verb's pagination flags and
// their defaults, and that get takes exactly one positional id.
func TestProfileListCommand_Flags(t *testing.T) {
	list := newProfileListCommand(nil)
	for flag, def := range map[string]string{"page": "1", "page-size": "20"} {
		f := list.Flags().Lookup(flag)
		if f == nil {
			t.Fatalf("list missing flag --%s", flag)
		}
		if f.DefValue != def {
			t.Errorf("--%s default = %q, want %q", flag, f.DefValue, def)
		}
	}
	get := newProfileGetCommand(nil)
	if err := get.Args(get, []string{}); err == nil {
		t.Error("get must require an id")
	}
	if err := get.Args(get, []string{"1", "2"}); err == nil {
		t.Error("get must take exactly one id")
	}
}

// TestRunProfileGet_InvalidID proves a non-numeric id fails with the typed
// error before any connection is attempted.
func TestRunProfileGet_InvalidID(t *testing.T) {
	get := newProfileGetCommand(func() *cli.CommonFlags { t.Fatal("flags must not be resolved for an invalid id"); return nil })
	err := get.RunE(get, []string{"not-a-number"})
	var invalid ErrInvalidProfileID
	if !errors.As(err, &invalid) || invalid.ID != "not-a-number" {
		t.Fatalf("expected ErrInvalidProfileID, got %v", err)
	}
}

// TestRunProfileList_InvalidPagination proves a page or page size below one
// fails with the typed error before any connection is attempted.
func TestRunProfileList_InvalidPagination(t *testing.T) {
	for _, tc := range []struct{ page, size int }{{0, 20}, {1, 0}, {-1, -1}} {
		err := runProfileList(nil, tc.page, tc.size)
		var invalid ErrInvalidPagination
		if !errors.As(err, &invalid) || invalid.Page != tc.page || invalid.PageSize != tc.size {
			t.Fatalf("page=%d size=%d: expected ErrInvalidPagination, got %v", tc.page, tc.size, err)
		}
	}
}

// TestBuildProfileListOutput pins the list envelope and that each item is the
// same shape as get, tls_server_name included, so an operator can find the
// compute profile and confirm its collector name in one call.
func TestBuildProfileListOutput(t *testing.T) {
	output := buildProfileListOutput(2, 20, 41, []*platformv1.DeviceProfile{
		{Id: 7, Name: "compute", Role: platformv1.DeviceRole_DEVICE_ROLE_WORKER, TlsServerName: "compute.trusted-platform.internal"},
		{Id: 8, Name: "gw", Role: platformv1.DeviceRole_DEVICE_ROLE_GATEWAY},
	})
	if output["page"] != 2 || output["page_size"] != 20 || output["total"] != 41 || output["total_pages"] != 3 {
		t.Fatalf("pagination envelope = %v", output)
	}
	items := output["profiles"].([]map[string]interface{})
	if len(items) != 2 || items[0]["id"] != "7" || items[0]["tls_server_name"] != "compute.trusted-platform.internal" {
		t.Fatalf("items = %v", items)
	}
	if _, present := items[1]["tls_server_name"]; present {
		t.Fatal("an unset tls_server_name must be omitted")
	}
	if empty := buildProfileListOutput(1, 20, 0, nil); len(empty["profiles"].([]map[string]interface{})) != 0 || empty["total_pages"] != 0 {
		t.Fatalf("empty list = %v", empty)
	}
}

// TestPrintProfileListTable_Empty proves an empty page prints the empty
// message rather than a header-only table (and does not panic on a nil
// printer path).
func TestPrintProfileListTable_Empty(t *testing.T) {
	printProfileListTable(nil, nil, 1, 20, 0)
}
