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

package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/viper"

	tpconfig "github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

func newTestHandlers(t *testing.T) *PlatformHandlers {
	t.Helper()
	l := logging.NewLogger(slog.LevelDebug, nil)
	w := response.NewResponseWriter(l, nil)
	return NewPlatformHandlers(l, w)
}

type fakeReloader struct {
	sections []string
	err      error
	called   bool
	snapID   string
}

func (f *fakeReloader) ReloadConfigFromDisk() ([]string, error) {
	f.called = true
	return f.sections, f.err
}

func (f *fakeReloader) ReloadConfigWithSnapshot(actor string) ([]string, string, error) {
	f.called = true
	return f.sections, f.snapID, f.err
}

func (f *fakeReloader) RollbackConfig(snapshotID, actor string) (string, error) {
	f.called = true
	return f.snapID, f.err
}

func (f *fakeReloader) SnapshotStore() tpconfig.SnapshotStore {
	return nil
}

func TestGetConfig_RedactsByDefault(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	yamlBody := []byte("ca:\n  password: hunter2\n  cn: cp.example.com\n")
	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(bytes.NewReader(yamlBody)); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	h := newTestHandlers(t)
	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()
	h.GetConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload := body["payload"].(map[string]any)
	if hidden, _ := payload["secrets_hidden"].(bool); !hidden {
		t.Errorf("expected secrets_hidden=true, got %v", payload["secrets_hidden"])
	}
	tree := payload["tree"].(map[string]any)
	ca := tree["ca"].(map[string]any)
	if ca["password"] == "hunter2" {
		t.Error("password leaked despite default redaction")
	}
}

func TestGetConfig_SectionFilter(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	yamlBody := []byte("a:\n  v: 1\nb:\n  v: 2\n")
	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(bytes.NewReader(yamlBody)); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}

	h := newTestHandlers(t)
	req := httptest.NewRequest(http.MethodGet, "/config?section=a", nil)
	rec := httptest.NewRecorder()
	h.GetConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"a"`) {
		t.Errorf("expected section a in body, got %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"b"`) {
		t.Errorf("section b should be filtered out, got %s", rec.Body.String())
	}
}

func TestGetConfig_SectionNotFound(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(bytes.NewReader([]byte("a: 1\n"))); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	h := newTestHandlers(t)
	req := httptest.NewRequest(http.MethodGet, "/config?section=does-not-exist", nil)
	rec := httptest.NewRecorder()
	h.GetConfig(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestReloadConfig_Unconfigured(t *testing.T) {
	h := newTestHandlers(t)
	req := httptest.NewRequest(http.MethodPost, "/config/reload", nil)
	rec := httptest.NewRecorder()
	h.ReloadConfig(rec, req)
	if rec.Code < 500 {
		t.Errorf("expected 5xx when reloader unset, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReloadConfig_Success(t *testing.T) {
	h := newTestHandlers(t)
	r := &fakeReloader{sections: []string{"ca", "tpm"}}
	h.SetConfigReloader(r)

	req := httptest.NewRequest(http.MethodPost, "/config/reload", nil)
	rec := httptest.NewRecorder()
	h.ReloadConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !r.called {
		t.Error("reloader was not called")
	}
}

func TestReloadConfig_Failure(t *testing.T) {
	h := newTestHandlers(t)
	h.SetConfigReloader(&fakeReloader{err: errors.New("disk gone")})
	req := httptest.NewRequest(http.MethodPost, "/config/reload", nil)
	rec := httptest.NewRecorder()
	h.ReloadConfig(rec, req)
	if rec.Code < 500 {
		t.Errorf("expected 5xx, got %d", rec.Code)
	}
}

func TestValidateConfig_Good(t *testing.T) {
	h := newTestHandlers(t)
	body := []byte("ca:\n  cn: cp.example.com\n")
	req := httptest.NewRequest(http.MethodPost, "/config/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ValidateConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"valid":true`) {
		t.Errorf("expected valid=true, got %s", rec.Body.String())
	}
}

func TestValidateConfig_Bad(t *testing.T) {
	h := newTestHandlers(t)
	body := []byte("this: is: not: yaml")
	req := httptest.NewRequest(http.MethodPost, "/config/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ValidateConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (validate always 200, ships issues in body)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"valid":false`) {
		t.Errorf("expected valid=false, got %s", rec.Body.String())
	}
}
