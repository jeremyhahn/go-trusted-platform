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

package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// These tests drive the real virtual media dispatch chain (standard DMTF
// Redfish, then the Supermicro OEM Redfish backend, then the legacy
// Supermicro CGI backend) against an in-process Redfish server.

const (
	vmBMCCollectionPath = "/redfish/v1/Managers/1/VirtualMedia"
	vmBMCMemberPath     = vmBMCCollectionPath + "/CD"
	vmBMCInsertPath     = vmBMCMemberPath + "/Actions/VirtualMedia.InsertMedia"
	vmBMCEjectPath      = vmBMCMemberPath + "/Actions/VirtualMedia.EjectMedia"
)

// vmBMCCall records one request the fake BMC served.
type vmBMCCall struct {
	method string
	path   string
	body   string
}

// vmBMCServer is a configurable fake Redfish BMC exposing both the DMTF
// VirtualMedia collection and the Supermicro OEM CfgCD resources.
type vmBMCServer struct {
	// members lists the VirtualMedia collection; empty means zero members.
	members []string
	// collectionStatus, when non-zero, fails the collection GET.
	collectionStatus int
	// member is the JSON body served for vmBMCMemberPath.
	member string
	// memberStatus, when non-zero, fails the member GET.
	memberStatus int
	// actionStatus, when non-zero, fails InsertMedia and EjectMedia.
	actionStatus int
	// smcStatus, when non-zero, fails every Supermicro OEM write.
	smcStatus int
	// smcBody is the error body served with smcStatus.
	smcBody string
	// cd1 and cfgCD are the JSON bodies of the OEM status resources; an
	// empty value serves 404.
	cd1   string
	cfgCD string
	// cd1Status, when non-zero, fails the CD1 GET with smcBody.
	cd1Status int

	mu    sync.Mutex
	calls []vmBMCCall
}

func (s *vmBMCServer) record(r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		body = nil
	}
	s.mu.Lock()
	s.calls = append(s.calls, vmBMCCall{method: r.Method, path: r.URL.Path, body: string(body)})
	s.mu.Unlock()
}

// writes returns the non-GET requests the server saw, in order.
func (s *vmBMCServer) writes() []vmBMCCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []vmBMCCall
	for _, c := range s.calls {
		if c.method != http.MethodGet {
			out = append(out, c)
		}
	}
	return out
}

func vmBMCReply(w http.ResponseWriter, status int, body string) {
	if status == 0 {
		status = http.StatusOK
	}
	if body == "" && status == http.StatusOK {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (s *vmBMCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.record(r)
	switch r.URL.Path {
	case vmBMCCollectionPath:
		if s.collectionStatus != 0 {
			vmBMCReply(w, s.collectionStatus, `{"error":{}}`)
			return
		}
		type ref struct {
			ID string `json:"@odata.id"`
		}
		refs := make([]ref, 0, len(s.members))
		for _, m := range s.members {
			refs = append(refs, ref{ID: m})
		}
		body, err := json.Marshal(map[string]any{"Members": refs})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		vmBMCReply(w, http.StatusOK, string(body))
	case vmBMCMemberPath:
		if s.memberStatus != 0 {
			vmBMCReply(w, s.memberStatus, `{"error":{}}`)
			return
		}
		vmBMCReply(w, http.StatusOK, s.member)
	case vmBMCInsertPath, vmBMCEjectPath, "/custom/insert", "/custom/eject":
		vmBMCReply(w, s.actionStatus, "")
	case smcIsoConfigUnmountPath, smcIsoConfigMountPath:
		vmBMCReply(w, s.smcStatus, s.smcBody)
	case smcVirtualMediaPath:
		if r.Method == http.MethodGet {
			s.serveStatus(w, 0, s.cfgCD)
			return
		}
		vmBMCReply(w, s.smcStatus, s.smcBody)
	case smcCD1Path:
		s.serveStatus(w, s.cd1Status, s.cd1)
	default:
		http.NotFound(w, r)
	}
}

func (s *vmBMCServer) serveStatus(w http.ResponseWriter, status int, body string) {
	if status != 0 {
		vmBMCReply(w, status, s.smcBody)
		return
	}
	if body == "" {
		vmBMCReply(w, http.StatusNotFound, `{"error":{}}`)
		return
	}
	vmBMCReply(w, http.StatusOK, body)
}

// newVmBMCClient returns a redfishClient whose discovery has already run
// against fake, identifying the system as manufacturer. advertise controls
// whether the manager advertised a VirtualMedia collection.
func newVmBMCClient(t *testing.T, fake *vmBMCServer, manufacturer string, advertise bool) *redfishClient {
	t.Helper()
	server := httptest.NewTLSServer(fake)
	t.Cleanup(server.Close)
	rc := newTestRedfishClient(t, server)
	rc.discovered = true
	rc.manufacturer.Store(manufacturer)
	rc.model.Store("X11SPM-F")
	if advertise {
		rc.virtualMediaPath.Store(vmBMCCollectionPath)
	}
	return rc
}

func vmBMCSpec(url string) *MediaSpec {
	return &MediaSpec{URL: url}
}

// assertVmBMCWrites compares the method and path of every write request.
func assertVmBMCWrites(t *testing.T, fake *vmBMCServer, want ...string) []vmBMCCall {
	t.Helper()
	got := fake.writes()
	gotKeys := make([]string, 0, len(got))
	for _, c := range got {
		gotKeys = append(gotKeys, c.method+" "+c.path)
	}
	if strings.Join(gotKeys, "\n") != strings.Join(want, "\n") {
		t.Fatalf("write requests:\n%s\nwant:\n%s", strings.Join(gotKeys, "\n"), strings.Join(want, "\n"))
	}
	return got
}

// assertVmBMCAttempts checks the backends recorded by an all-backends failure.
func assertVmBMCAttempts(t *testing.T, err error, want ...string) {
	t.Helper()
	var all ErrVirtualMediaAllBackendsFailed
	if !errors.As(err, &all) {
		t.Fatalf("error = %v, want ErrVirtualMediaAllBackendsFailed", err)
	}
	got := make([]string, 0, len(all.Attempts))
	for _, a := range all.Attempts {
		got = append(got, a.Backend)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("attempts = %v, want %v", got, want)
	}
}

// assertVmBMCBackendFailed checks a short-circuit failure from backend.
func assertVmBMCBackendFailed(t *testing.T, err error, backend string) ErrVirtualMediaBackendFailed {
	t.Helper()
	var failed ErrVirtualMediaBackendFailed
	if !errors.As(err, &failed) {
		t.Fatalf("error = %v, want ErrVirtualMediaBackendFailed", err)
	}
	if failed.Backend != backend {
		t.Fatalf("failed backend = %q, want %q", failed.Backend, backend)
	}
	return failed
}

const vmBMCLicenseBody = `{"error":{"@Message.ExtendedInfo":[{"MessageId":"SMC.1.0.OemLicenseNotPassed"}]}}`

func TestVmBMC_MountStandardUsesAdvertisedInsertTarget(t *testing.T) {
	fake := &vmBMCServer{
		members: []string{vmBMCMemberPath},
		member:  `{"MediaTypes":["CD","DVD"],"Actions":{"#VirtualMedia.InsertMedia":{"@odata.id":"/custom/insert"}}}`,
	}
	rc := newVmBMCClient(t, fake, "Dell Inc.", true)

	if err := rc.MountVirtualMedia(context.Background(), vmBMCSpec("https://images/boot.iso")); err != nil {
		t.Fatalf("MountVirtualMedia() error: %v", err)
	}
	calls := assertVmBMCWrites(t, fake, "POST /custom/insert")
	if !strings.Contains(calls[0].body, `"Image":"https://images/boot.iso"`) {
		t.Errorf("insert body = %s, want the image URL", calls[0].body)
	}
}

func TestVmBMC_MountStandardDefaultsInsertPath(t *testing.T) {
	fake := &vmBMCServer{members: []string{vmBMCMemberPath}, member: `{"MediaTypes":["USBStick"]}`}
	rc := newVmBMCClient(t, fake, "Dell Inc.", true)

	if err := rc.MountVirtualMedia(context.Background(), vmBMCSpec("http://images/boot.iso")); err != nil {
		t.Fatalf("MountVirtualMedia() error: %v", err)
	}
	assertVmBMCWrites(t, fake, "POST "+vmBMCInsertPath)
}

func TestVmBMC_MountSupermicroFallsThroughOnInsert404(t *testing.T) {
	fake := &vmBMCServer{
		members:      []string{vmBMCMemberPath},
		member:       `{"MediaTypes":["CD"]}`,
		actionStatus: http.StatusNotFound,
	}
	rc := newVmBMCClient(t, fake, "Supermicro", true)

	if err := rc.MountVirtualMedia(context.Background(), vmBMCSpec("http://10.0.0.5:8080/iso/boot.iso")); err != nil {
		t.Fatalf("MountVirtualMedia() error: %v", err)
	}
	calls := assertVmBMCWrites(t, fake,
		"POST "+vmBMCInsertPath,
		"POST "+smcIsoConfigUnmountPath,
		"PATCH "+smcVirtualMediaPath,
		"POST "+smcIsoConfigMountPath,
	)
	if calls[2].body != `{"Host":"10.0.0.5:8080","Path":"/iso/boot.iso"}` {
		t.Errorf("CfgCD body = %s, want Host and Path only", calls[2].body)
	}
}

func TestVmBMC_MountDellInsert404IsFatal(t *testing.T) {
	fake := &vmBMCServer{
		members:      []string{vmBMCMemberPath},
		member:       `{"MediaTypes":["CD"]}`,
		actionStatus: http.StatusNotFound,
	}
	rc := newVmBMCClient(t, fake, "Dell Inc.", true)

	err := rc.MountVirtualMedia(context.Background(), vmBMCSpec("http://images/boot.iso"))
	failed := assertVmBMCBackendFailed(t, err, "redfish-std")
	var reqErr ErrRedfishRequest
	if !errors.As(failed.Cause, &reqErr) || reqErr.StatusCode != http.StatusNotFound {
		t.Errorf("cause = %v, want the 404 ErrRedfishRequest", failed.Cause)
	}
	assertVmBMCWrites(t, fake, "POST "+vmBMCInsertPath)
}

func TestVmBMC_MountFallsThroughWithoutStandardCollection(t *testing.T) {
	tests := []struct {
		name      string
		members   []string
		advertise bool
	}{
		{name: "empty collection", advertise: true},
		{name: "collection not advertised", members: []string{vmBMCMemberPath}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &vmBMCServer{members: tt.members}
			rc := newVmBMCClient(t, fake, "Dell Inc.", tt.advertise)

			if err := rc.MountVirtualMedia(context.Background(), vmBMCSpec("https://images/boot.iso")); err != nil {
				t.Fatalf("MountVirtualMedia() error: %v", err)
			}
			assertVmBMCWrites(t, fake,
				"POST "+smcIsoConfigUnmountPath,
				"PATCH "+smcVirtualMediaPath,
				"POST "+smcIsoConfigMountPath,
			)
		})
	}
}

func TestVmBMC_MountCIFSSkipsStandardBackend(t *testing.T) {
	fake := &vmBMCServer{members: []string{vmBMCMemberPath}, member: `{"MediaTypes":["CD"]}`}
	rc := newVmBMCClient(t, fake, "Supermicro", true)

	spec := &MediaSpec{URL: "cifs://fileserver/share/boot.iso", Username: "u", Password: "p"}
	if err := rc.MountVirtualMedia(context.Background(), spec); err != nil {
		t.Fatalf("MountVirtualMedia() error: %v", err)
	}
	calls := assertVmBMCWrites(t, fake,
		"POST "+smcIsoConfigUnmountPath,
		"PATCH "+smcVirtualMediaPath,
		"POST "+smcIsoConfigMountPath,
	)
	if calls[1].body != `{"Host":"fileserver","Path":"/share/boot.iso","Username":"u","Password":"p"}` {
		t.Errorf("CfgCD body = %s, want the CIFS share split", calls[1].body)
	}
}

func TestVmBMC_MountCIFSReachesUnsupportedCGIBackend(t *testing.T) {
	fake := &vmBMCServer{smcStatus: http.StatusNotFound}
	rc := newVmBMCClient(t, fake, "Supermicro", false)

	err := rc.MountVirtualMedia(context.Background(), vmBMCSpec("cifs://fileserver/share/boot.iso"))
	assertVmBMCAttempts(t, err, "redfish-smc", "smc-cgi")
}

func TestVmBMC_MountNFSHasNoBackend(t *testing.T) {
	fake := &vmBMCServer{}
	rc := newVmBMCClient(t, fake, "Supermicro", true)

	err := rc.MountVirtualMedia(context.Background(), vmBMCSpec("nfs://fileserver/export/boot.iso"))
	assertVmBMCAttempts(t, err)
	assertVmBMCWrites(t, fake)
}

func TestVmBMC_MountLicenseRequiredFallsThrough(t *testing.T) {
	fake := &vmBMCServer{
		members:      []string{vmBMCMemberPath},
		member:       `{"MediaTypes":["CD"]}`,
		actionStatus: http.StatusNotFound,
		smcStatus:    http.StatusForbidden,
		smcBody:      vmBMCLicenseBody,
	}
	rc := newVmBMCClient(t, fake, "Supermicro", true)

	err := rc.MountVirtualMedia(context.Background(), vmBMCSpec("https://images/boot.iso"))
	assertVmBMCAttempts(t, err, "redfish-std", "redfish-smc")
	var all ErrVirtualMediaAllBackendsFailed
	if !errors.As(err, &all) {
		t.Fatalf("error = %v, want ErrVirtualMediaAllBackendsFailed", err)
	}
	var lic ErrVirtualMediaLicenseRequired
	if !errors.As(all.Attempts[1].Err, &lic) || lic.License != "DCMS" {
		t.Errorf("redfish-smc attempt = %v, want the DCMS license error", all.Attempts[1].Err)
	}
}

func TestVmBMC_MountErrors(t *testing.T) {
	tests := []struct {
		name      string
		fake      *vmBMCServer
		closed    bool
		wantCause func(error) bool
	}{
		{
			name:   "closed client",
			fake:   &vmBMCServer{},
			closed: true,
			wantCause: func(err error) bool {
				var closed ErrClientClosed
				return errors.As(err, &closed)
			},
		},
		{
			name: "collection read fails",
			fake: &vmBMCServer{collectionStatus: http.StatusInternalServerError},
			wantCause: func(err error) bool {
				var disc ErrRedfishDiscovery
				return errors.As(err, &disc) && disc.Resource == "VirtualMedia members"
			},
		},
		{
			name: "member read fails",
			fake: &vmBMCServer{members: []string{vmBMCMemberPath}, memberStatus: http.StatusInternalServerError},
			wantCause: func(err error) bool {
				var reqErr ErrRedfishRequest
				return errors.As(err, &reqErr) && reqErr.StatusCode == http.StatusInternalServerError
			},
		},
		{
			name: "insert fails",
			fake: &vmBMCServer{
				members:      []string{vmBMCMemberPath},
				member:       `{"MediaTypes":["CD"]}`,
				actionStatus: http.StatusInternalServerError,
			},
			wantCause: func(err error) bool {
				var reqErr ErrRedfishRequest
				return errors.As(err, &reqErr) && reqErr.StatusCode == http.StatusInternalServerError
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := newVmBMCClient(t, tt.fake, "Supermicro", true)
			if tt.closed {
				rc.closed.Store(true)
			}
			err := rc.MountVirtualMedia(context.Background(), vmBMCSpec("https://images/boot.iso"))
			failed := assertVmBMCBackendFailed(t, err, "redfish-std")
			if !tt.wantCause(failed.Cause) {
				t.Errorf("cause = %v (%T), not the expected typed error", failed.Cause, failed.Cause)
			}
		})
	}
}

func TestVmBMC_MountRejectsInvalidSpec(t *testing.T) {
	fake := &vmBMCServer{}
	rc := newVmBMCClient(t, fake, "Supermicro", true)

	err := rc.MountVirtualMedia(context.Background(), vmBMCSpec("gopher://images/boot.iso"))
	var invalid ErrVirtualMediaInvalidSpec
	if !errors.As(err, &invalid) || invalid.Field != "URL" {
		t.Fatalf("error = %v, want ErrVirtualMediaInvalidSpec on URL", err)
	}
	assertVmBMCWrites(t, fake)
}

func TestVmBMC_UnmountStandardUsesAdvertisedEjectTarget(t *testing.T) {
	fake := &vmBMCServer{
		members: []string{vmBMCMemberPath},
		member:  `{"MediaTypes":["CD"],"Actions":{"#VirtualMedia.EjectMedia":{"@odata.id":"/custom/eject"}}}`,
	}
	rc := newVmBMCClient(t, fake, "Dell Inc.", true)

	if err := rc.UnmountVirtualMedia(context.Background()); err != nil {
		t.Fatalf("UnmountVirtualMedia() error: %v", err)
	}
	assertVmBMCWrites(t, fake, "POST /custom/eject")
}

func TestVmBMC_UnmountEmptyCollectionIsSuccess(t *testing.T) {
	fake := &vmBMCServer{}
	rc := newVmBMCClient(t, fake, "Supermicro", true)

	if err := rc.UnmountVirtualMedia(context.Background()); err != nil {
		t.Fatalf("UnmountVirtualMedia() error: %v", err)
	}
	// The standard backend owns the answer: the OEM backend is never asked.
	assertVmBMCWrites(t, fake)
}

func TestVmBMC_UnmountFallsThroughToSupermicro(t *testing.T) {
	tests := []struct {
		name      string
		fake      *vmBMCServer
		advertise bool
		want      []string
	}{
		{
			name: "collection not advertised",
			fake: &vmBMCServer{},
			want: []string{"POST " + smcIsoConfigUnmountPath, "PATCH " + smcVirtualMediaPath},
		},
		{
			name: "eject 404 on Supermicro",
			fake: &vmBMCServer{
				members:      []string{vmBMCMemberPath},
				member:       `{"MediaTypes":["CD"]}`,
				actionStatus: http.StatusNotFound,
			},
			advertise: true,
			want: []string{
				"POST " + vmBMCEjectPath,
				"POST " + smcIsoConfigUnmountPath,
				"PATCH " + smcVirtualMediaPath,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := newVmBMCClient(t, tt.fake, "Supermicro", tt.advertise)
			if err := rc.UnmountVirtualMedia(context.Background()); err != nil {
				t.Fatalf("UnmountVirtualMedia() error: %v", err)
			}
			calls := assertVmBMCWrites(t, tt.fake, tt.want...)
			if last := calls[len(calls)-1]; last.body != `{}` {
				t.Errorf("CfgCD clear body = %s, want {}", last.body)
			}
		})
	}
}

func TestVmBMC_UnmountErrors(t *testing.T) {
	t.Run("Dell eject 404 is fatal", func(t *testing.T) {
		fake := &vmBMCServer{
			members:      []string{vmBMCMemberPath},
			member:       `{"MediaTypes":["CD"]}`,
			actionStatus: http.StatusNotFound,
		}
		rc := newVmBMCClient(t, fake, "Dell Inc.", true)
		err := rc.UnmountVirtualMedia(context.Background())
		assertVmBMCBackendFailed(t, err, "redfish-std")
	})
	t.Run("collection read fails", func(t *testing.T) {
		fake := &vmBMCServer{collectionStatus: http.StatusInternalServerError}
		rc := newVmBMCClient(t, fake, "Supermicro", true)
		err := rc.UnmountVirtualMedia(context.Background())
		failed := assertVmBMCBackendFailed(t, err, "redfish-std")
		var disc ErrRedfishDiscovery
		if !errors.As(failed.Cause, &disc) {
			t.Errorf("cause = %v, want ErrRedfishDiscovery", failed.Cause)
		}
	})
	t.Run("member read fails", func(t *testing.T) {
		fake := &vmBMCServer{members: []string{vmBMCMemberPath}, memberStatus: http.StatusInternalServerError}
		rc := newVmBMCClient(t, fake, "Supermicro", true)
		err := rc.UnmountVirtualMedia(context.Background())
		assertVmBMCBackendFailed(t, err, "redfish-std")
	})
	t.Run("closed client", func(t *testing.T) {
		rc := newVmBMCClient(t, &vmBMCServer{}, "Supermicro", true)
		rc.closed.Store(true)
		err := rc.UnmountVirtualMedia(context.Background())
		failed := assertVmBMCBackendFailed(t, err, "redfish-std")
		var closed ErrClientClosed
		if !errors.As(failed.Cause, &closed) {
			t.Errorf("cause = %v, want ErrClientClosed", failed.Cause)
		}
	})
	t.Run("Supermicro clear fails", func(t *testing.T) {
		fake := &vmBMCServer{smcStatus: http.StatusInternalServerError, smcBody: `{"error":"busy"}`}
		rc := newVmBMCClient(t, fake, "Supermicro", false)
		err := rc.UnmountVirtualMedia(context.Background())
		failed := assertVmBMCBackendFailed(t, err, "redfish-smc")
		var reqErr ErrRedfishRequest
		if !errors.As(failed.Cause, &reqErr) || reqErr.Message != `{"error":"busy"}` {
			t.Errorf("cause = %v, want the BMC error body", failed.Cause)
		}
	})
	t.Run("every backend unsupported", func(t *testing.T) {
		fake := &vmBMCServer{smcStatus: http.StatusNotFound}
		rc := newVmBMCClient(t, fake, "Supermicro", false)
		err := rc.UnmountVirtualMedia(context.Background())
		assertVmBMCAttempts(t, err, "redfish-std", "redfish-smc", "smc-cgi")
	})
}

func TestVmBMC_StatusFromStandardMember(t *testing.T) {
	tests := []struct {
		name   string
		member string
		want   VirtualMediaInfo
	}{
		{
			name:   "inserted DVD",
			member: `{"Inserted":true,"Image":"https://images/boot.iso","MediaTypes":["DVD","CD"]}`,
			want:   VirtualMediaInfo{Mounted: true, ImageURL: "https://images/boot.iso", MediaType: "dvd"},
		},
		{
			name:   "empty slot without media types",
			member: `{"Inserted":false}`,
			want:   VirtualMediaInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &vmBMCServer{members: []string{vmBMCMemberPath}, member: tt.member}
			rc := newVmBMCClient(t, fake, "Supermicro", true)
			info, err := rc.VirtualMediaStatus(context.Background())
			if err != nil {
				t.Fatalf("VirtualMediaStatus() error: %v", err)
			}
			if *info != tt.want {
				t.Errorf("VirtualMediaStatus() = %+v, want %+v", *info, tt.want)
			}
		})
	}
}

func TestVmBMC_StatusFallsThroughToSupermicro(t *testing.T) {
	tests := []struct {
		name string
		fake *vmBMCServer
		want VirtualMediaInfo
	}{
		{
			name: "CD1 inserted",
			fake: &vmBMCServer{cd1: `{"Inserted":true,"Image":"http://h/boot.iso"}`},
			want: VirtualMediaInfo{Mounted: true, ImageURL: "http://h/boot.iso", MediaType: "cd"},
		},
		{
			name: "CfgCD Host and Path only",
			fake: &vmBMCServer{cfgCD: `{"Host":"10.0.0.5:8080","Path":"/iso/boot.iso"}`},
			want: VirtualMediaInfo{Mounted: true, ImageURL: "http://10.0.0.5:8080/iso/boot.iso", MediaType: "cd"},
		},
		{
			name: "CfgCD empty",
			fake: &vmBMCServer{cfgCD: `{}`},
			want: VirtualMediaInfo{MediaType: "cd"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := newVmBMCClient(t, tt.fake, "Supermicro", true)
			info, err := rc.VirtualMediaStatus(context.Background())
			if err != nil {
				t.Fatalf("VirtualMediaStatus() error: %v", err)
			}
			if *info != tt.want {
				t.Errorf("VirtualMediaStatus() = %+v, want %+v", *info, tt.want)
			}
		})
	}
}

func TestVmBMC_StatusErrors(t *testing.T) {
	tests := []struct {
		name      string
		fake      *vmBMCServer
		advertise bool
		check     func(t *testing.T, err error)
	}{
		{
			name:      "collection read fails",
			fake:      &vmBMCServer{collectionStatus: http.StatusInternalServerError},
			advertise: true,
			check: func(t *testing.T, err error) {
				failed := assertVmBMCBackendFailed(t, err, "redfish-std")
				var disc ErrRedfishDiscovery
				if !errors.As(failed.Cause, &disc) {
					t.Errorf("cause = %v, want ErrRedfishDiscovery", failed.Cause)
				}
			},
		},
		{
			name:      "member read fails",
			fake:      &vmBMCServer{members: []string{vmBMCMemberPath}, memberStatus: http.StatusBadGateway},
			advertise: true,
			check: func(t *testing.T, err error) {
				assertVmBMCBackendFailed(t, err, "redfish-std")
			},
		},
		{
			name: "CD1 server error",
			fake: &vmBMCServer{cd1Status: http.StatusInternalServerError, smcBody: `{"error":"boom"}`},
			check: func(t *testing.T, err error) {
				failed := assertVmBMCBackendFailed(t, err, "redfish-smc")
				var reqErr ErrRedfishRequest
				if !errors.As(failed.Cause, &reqErr) || reqErr.StatusCode != http.StatusInternalServerError ||
					reqErr.Path != smcCD1Path || reqErr.Message != `{"error":"boom"}` {
					t.Errorf("cause = %+v, want the CD1 500 with its body", failed.Cause)
				}
			},
		},
		{
			name: "CD1 bad JSON",
			fake: &vmBMCServer{cd1: `{"Inserted":`},
			check: func(t *testing.T, err error) {
				failed := assertVmBMCBackendFailed(t, err, "redfish-smc")
				var reqErr ErrRedfishRequest
				if !errors.As(failed.Cause, &reqErr) || reqErr.Cause == nil {
					t.Errorf("cause = %v, want an ErrRedfishRequest wrapping the decode error", failed.Cause)
				}
			},
		},
		{
			name: "CD1 license required",
			fake: &vmBMCServer{cd1Status: http.StatusForbidden, smcBody: vmBMCLicenseBody},
			check: func(t *testing.T, err error) {
				assertVmBMCAttempts(t, err, "redfish-std", "redfish-smc", "smc-cgi")
			},
		},
		{
			name: "no virtual media anywhere",
			fake: &vmBMCServer{},
			check: func(t *testing.T, err error) {
				assertVmBMCAttempts(t, err, "redfish-std", "redfish-smc", "smc-cgi")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := newVmBMCClient(t, tt.fake, "Supermicro", tt.advertise)
			info, err := rc.VirtualMediaStatus(context.Background())
			if info != nil {
				t.Fatalf("VirtualMediaStatus() info = %+v, want nil on error", info)
			}
			var vmErr ErrVirtualMedia
			if !errors.As(err, &vmErr) || vmErr.Operation != "status" {
				t.Fatalf("error = %v, want ErrVirtualMedia for status", err)
			}
			tt.check(t, err)
		})
	}
}

func TestVmBMC_SmcRequestHelperErrors(t *testing.T) {
	short := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Declare more body than is sent so reading the error body fails.
		w.Header().Set("Content-Length", "64")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "short")
	}))
	t.Cleanup(short.Close)
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	closed.Close()

	tests := []struct {
		name   string
		server *httptest.Server
		method string
		body   any
		check  func(t *testing.T, reqErr ErrRedfishRequest)
	}{
		{
			name:   "body cannot be encoded",
			server: short,
			method: http.MethodPatch,
			body:   map[string]any{"bad": make(chan int)},
			check: func(t *testing.T, reqErr ErrRedfishRequest) {
				var typeErr *json.UnsupportedTypeError
				if !errors.As(reqErr, &typeErr) {
					t.Errorf("cause = %v, want *json.UnsupportedTypeError", reqErr.Cause)
				}
			},
		},
		{
			name:   "invalid method",
			server: short,
			method: "BAD METHOD",
			body:   map[string]any{},
			check: func(t *testing.T, reqErr ErrRedfishRequest) {
				if reqErr.Cause == nil || reqErr.Method != "BAD METHOD" {
					t.Errorf("error = %+v, want the request build failure", reqErr)
				}
			},
		},
		{
			name:   "server unreachable",
			server: closed,
			method: http.MethodPost,
			body:   map[string]any{},
			check: func(t *testing.T, reqErr ErrRedfishRequest) {
				if reqErr.Cause == nil || reqErr.StatusCode != 0 {
					t.Errorf("error = %+v, want a transport failure", reqErr)
				}
			},
		},
		{
			name:   "error body cut short",
			server: short,
			method: http.MethodPost,
			body:   map[string]any{},
			check: func(t *testing.T, reqErr ErrRedfishRequest) {
				if reqErr.StatusCode != http.StatusInternalServerError || reqErr.Message != "500 Internal Server Error" {
					t.Errorf("error = %+v, want the HTTP status as the message", reqErr)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newVmediaRedfishSmc(newSmcTestClient(t, tt.server))
			err := backend.do(context.Background(), tt.method, smcIsoConfigMountPath, tt.body)
			var reqErr ErrRedfishRequest
			if !errors.As(err, &reqErr) {
				t.Fatalf("do() error = %v, want ErrRedfishRequest", err)
			}
			if reqErr.Path != smcIsoConfigMountPath {
				t.Errorf("Path = %q, want %q", reqErr.Path, smcIsoConfigMountPath)
			}
			tt.check(t, reqErr)
		})
	}
}

func TestVmBMC_SmcStatusRequestErrors(t *testing.T) {
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	closed.Close()

	t.Run("invalid base URL", func(t *testing.T) {
		rc := newSmcTestClient(t, closed)
		rc.transport.baseURL = "http://bmc\x7f"
		_, err := newVmediaRedfishSmc(rc).Status(context.Background())
		var reqErr ErrRedfishRequest
		if !errors.As(err, &reqErr) || reqErr.Path != smcCD1Path || reqErr.Cause == nil {
			t.Fatalf("Status() error = %v, want the CD1 request build failure", err)
		}
	})
	t.Run("server unreachable", func(t *testing.T) {
		_, err := newVmediaRedfishSmc(newSmcTestClient(t, closed)).Status(context.Background())
		var reqErr ErrRedfishRequest
		if !errors.As(err, &reqErr) || reqErr.Method != http.MethodGet || reqErr.Cause == nil {
			t.Fatalf("Status() error = %v, want a transport failure", err)
		}
	})
}

func TestSplitHTTPURL(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPath string
	}{
		{in: "http://10.0.0.5:8080/iso/boot.iso", wantHost: "10.0.0.5:8080", wantPath: "/iso/boot.iso"},
		{in: "https://images.example/boot.iso?sig=abc", wantHost: "images.example", wantPath: "/boot.iso?sig=abc"},
		{in: "https://images.example", wantHost: "images.example", wantPath: "/"},
		{in: "cifs://server/share/boot.iso", wantHost: "", wantPath: "cifs://server/share/boot.iso"},
		{in: "", wantHost: "", wantPath: ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			host, path := splitHTTPURL(tt.in)
			if host != tt.wantHost || path != tt.wantPath {
				t.Errorf("splitHTTPURL(%q) = (%q, %q), want (%q, %q)", tt.in, host, path, tt.wantHost, tt.wantPath)
			}
		})
	}
}
