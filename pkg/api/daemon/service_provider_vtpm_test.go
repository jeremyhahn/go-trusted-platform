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

package daemon

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// TestPlatformServiceProvider_VTPMGet_Success exercises VTPMGet happy path.
func TestPlatformServiceProvider_VTPMGet_Success(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		getBundleFunc: func(ctx context.Context, id string) (*vtpm.Bundle, error) {
			return &vtpm.Bundle{ID: id}, nil
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mock,
	})

	result, err := provider.VTPMGet(ctx, "test-bundle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bundle, ok := result.(*vtpm.Bundle)
	if !ok {
		t.Fatalf("expected *vtpm.Bundle, got %T", result)
	}
	if bundle.ID != "test-bundle" {
		t.Errorf("expected ID test-bundle, got %s", bundle.ID)
	}
}

// TestPlatformServiceProvider_VTPMGet_NilService verifies nil service check.
func TestPlatformServiceProvider_VTPMGet_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.VTPMGet(ctx, "test")
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// TestPlatformServiceProvider_VTPMGet_Error verifies error propagation.
func TestPlatformServiceProvider_VTPMGet_Error(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		getBundleFunc: func(ctx context.Context, id string) (*vtpm.Bundle, error) {
			return nil, errors.New("not found")
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mock,
	})

	_, err := provider.VTPMGet(ctx, "test-bundle")
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestPlatformServiceProvider_VTPMValidate_Success exercises VTPMValidate valid bundle.
func TestPlatformServiceProvider_VTPMValidate_Success(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		validateBundleFunc: func(ctx context.Context, id string) error {
			return nil
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mock,
	})

	result, err := provider.VTPMValidate(ctx, "test-bundle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}
	if valid, ok := m["valid"].(bool); !ok || !valid {
		t.Error("expected valid=true")
	}
}

// TestPlatformServiceProvider_VTPMValidate_Invalid exercises validation failure.
func TestPlatformServiceProvider_VTPMValidate_Invalid(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		validateBundleFunc: func(ctx context.Context, id string) error {
			return errors.New("integrity check failed")
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mock,
	})

	result, err := provider.VTPMValidate(ctx, "test-bundle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}
	if valid, ok := m["valid"].(bool); !ok || valid {
		t.Error("expected valid=false")
	}
}

// TestPlatformServiceProvider_VTPMValidate_NotFound exercises not-found propagation.
func TestPlatformServiceProvider_VTPMValidate_NotFound(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		validateBundleFunc: func(ctx context.Context, id string) error {
			return vtpm.ErrBundleNotFound{ID: id}
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mock,
	})

	_, err := provider.VTPMValidate(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	var notFound vtpm.ErrBundleNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrBundleNotFound, got %T: %v", err, err)
	}
}

// TestPlatformServiceProvider_VTPMExport_Success exercises VTPMExport happy path.
func TestPlatformServiceProvider_VTPMExport_Success(t *testing.T) {
	ctx := context.Background()
	testData := []byte("test archive data")
	mock := &mockVTPMService{
		exportBundleFunc: func(ctx context.Context, id string, w io.Writer) error {
			_, err := w.Write(testData)
			return err
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mock,
	})

	result, err := provider.VTPMExport(ctx, "test-bundle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}
	if m["id"] != "test-bundle" {
		t.Errorf("expected id=test-bundle, got %v", m["id"])
	}
	if size, ok := m["size"].(int64); !ok || size != int64(len(testData)) {
		t.Errorf("expected size=%d, got %v", len(testData), m["size"])
	}
}

// TestPlatformServiceProvider_VTPMExport_Error exercises error propagation.
func TestPlatformServiceProvider_VTPMExport_Error(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		exportBundleFunc: func(ctx context.Context, id string, w io.Writer) error {
			return errors.New("export failed")
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mock,
	})

	_, err := provider.VTPMExport(ctx, "test-bundle")
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestPlatformServiceProvider_VTPMImport_Success exercises VTPMImport happy path.
func TestPlatformServiceProvider_VTPMImport_Success(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		importBundleFunc: func(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
			return &vtpm.Bundle{ID: "imported"}, nil
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mock,
	})

	result, err := provider.VTPMImport(ctx, []byte("archive data"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bundle, ok := result.(*vtpm.Bundle)
	if !ok {
		t.Fatalf("expected *vtpm.Bundle, got %T", result)
	}
	if bundle.ID != "imported" {
		t.Errorf("expected ID imported, got %s", bundle.ID)
	}
}

// TestPlatformServiceProvider_VTPMImport_Error exercises import error.
func TestPlatformServiceProvider_VTPMImport_Error(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		importBundleFunc: func(ctx context.Context, r io.Reader) (*vtpm.Bundle, error) {
			return nil, errors.New("invalid archive")
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{
		VTPMService: mock,
	})

	_, err := provider.VTPMImport(ctx, []byte("bad data"))
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestPlatformServiceProvider_VTPMCreateTemplate exercises template creation.
func TestPlatformServiceProvider_VTPMCreateTemplate(t *testing.T) {
	ctx := context.Background()

	t.Run("RSA", func(t *testing.T) {
		mock := &mockVTPMService{
			createTemplateFunc: func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
				if opts.EKAlgorithm != vtpm.EKAlgorithmRSA {
					t.Errorf("expected RSA algorithm, got %v", opts.EKAlgorithm)
				}
				return &vtpm.Template{ID: opts.ID}, nil
			},
		}
		provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: mock})
		result, err := provider.VTPMCreateTemplate(ctx, "tpl1", "desc", "RSA", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		tpl, ok := result.(*vtpm.Template)
		if !ok {
			t.Fatalf("expected *vtpm.Template, got %T", result)
		}
		if tpl.ID != "tpl1" {
			t.Errorf("expected ID=tpl1, got %s", tpl.ID)
		}
	})

	t.Run("ECC", func(t *testing.T) {
		mock := &mockVTPMService{
			createTemplateFunc: func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
				if opts.EKAlgorithm != vtpm.EKAlgorithmECC {
					t.Errorf("expected ECC algorithm, got %v", opts.EKAlgorithm)
				}
				return &vtpm.Template{ID: opts.ID}, nil
			},
		}
		provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: mock})
		_, err := provider.VTPMCreateTemplate(ctx, "tpl2", "desc", "ECC", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("error", func(t *testing.T) {
		mock := &mockVTPMService{
			createTemplateFunc: func(ctx context.Context, opts *vtpm.CreateTemplateOptions) (*vtpm.Template, error) {
				return nil, errors.New("template creation failed")
			},
		}
		provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: mock})
		_, err := provider.VTPMCreateTemplate(ctx, "tpl3", "desc", "RSA", false)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// TestPlatformServiceProvider_VTPMGetTemplate exercises template retrieval.
func TestPlatformServiceProvider_VTPMGetTemplate(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		getTemplateFunc: func(ctx context.Context, id string) (*vtpm.Template, error) {
			return &vtpm.Template{ID: id}, nil
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: mock})

	result, err := provider.VTPMGetTemplate(ctx, "tpl1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tpl, ok := result.(*vtpm.Template)
	if !ok {
		t.Fatalf("expected *vtpm.Template, got %T", result)
	}
	if tpl.ID != "tpl1" {
		t.Errorf("expected ID=tpl1, got %s", tpl.ID)
	}
}

// TestPlatformServiceProvider_VTPMDeleteTemplate exercises template deletion.
func TestPlatformServiceProvider_VTPMDeleteTemplate(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		deleteTemplateFunc: func(ctx context.Context, id string) error {
			return nil
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: mock})

	err := provider.VTPMDeleteTemplate(ctx, "tpl1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPlatformServiceProvider_VTPMListTemplates exercises template listing.
func TestPlatformServiceProvider_VTPMListTemplates(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		listTemplatesFunc: func(ctx context.Context) ([]*vtpm.Template, error) {
			return []*vtpm.Template{{ID: "tpl1"}, {ID: "tpl2"}}, nil
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: mock})

	result, err := provider.VTPMListTemplates(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", result)
	}
	if total, ok := m["total"].(int); !ok || total != 2 {
		t.Errorf("expected total=2, got %v", m["total"])
	}
}

// TestPlatformServiceProvider_VTPMCloneTemplate exercises template cloning.
func TestPlatformServiceProvider_VTPMCloneTemplate(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		cloneTemplateFunc: func(ctx context.Context, opts *vtpm.CloneOptions) (*vtpm.Bundle, error) {
			return &vtpm.Bundle{ID: opts.Hostname}, nil
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: mock})

	result, err := provider.VTPMCloneTemplate(ctx, "tpl1", "new-host", map[string]string{"env": "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bundle, ok := result.(*vtpm.Bundle)
	if !ok {
		t.Fatalf("expected *vtpm.Bundle, got %T", result)
	}
	if bundle.ID != "new-host" {
		t.Errorf("expected ID new-host, got %s", bundle.ID)
	}
}

// TestPlatformServiceProvider_VTPMPaths exercises path retrieval methods.
func TestPlatformServiceProvider_VTPMPaths(t *testing.T) {
	ctx := context.Background()
	mock := &mockVTPMService{
		getBundlePathFunc: func(id string) string {
			return "/var/lib/vtpm/" + id
		},
		getTPMSocketPathFunc: func(id string) string {
			return "/var/run/vtpm/" + id + ".sock"
		},
		getNVRAMPathFunc: func(id string) string {
			return "/var/lib/vtpm/" + id + "/nvram.fd"
		},
	}
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: mock})

	t.Run("GetBundlePath", func(t *testing.T) {
		result, err := provider.VTPMGetBundlePath(ctx, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if m["path"] != "/var/lib/vtpm/test" {
			t.Errorf("unexpected path: %v", m["path"])
		}
	})

	t.Run("GetTPMSocketPath", func(t *testing.T) {
		result, err := provider.VTPMGetTPMSocketPath(ctx, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if m["path"] != "/var/run/vtpm/test.sock" {
			t.Errorf("unexpected path: %v", m["path"])
		}
	})

	t.Run("GetNVRAMPath", func(t *testing.T) {
		result, err := provider.VTPMGetNVRAMPath(ctx, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if m["path"] != "/var/lib/vtpm/test/nvram.fd" {
			t.Errorf("unexpected path: %v", m["path"])
		}
	})
}

// TestPlatformServiceProvider_VTPMIsRunning exercises running status check.
func TestPlatformServiceProvider_VTPMIsRunning(t *testing.T) {
	ctx := context.Background()

	t.Run("running", func(t *testing.T) {
		mock := &mockVTPMService{
			isRunningFunc: func(bundleID string) bool { return true },
		}
		provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: mock})
		result, err := provider.VTPMIsRunning(ctx, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if running, ok := m["running"].(bool); !ok || !running {
			t.Error("expected running=true")
		}
	})

	t.Run("not running", func(t *testing.T) {
		mock := &mockVTPMService{
			isRunningFunc: func(bundleID string) bool { return false },
		}
		provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{VTPMService: mock})
		result, err := provider.VTPMIsRunning(ctx, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		m := result.(map[string]interface{})
		if running, ok := m["running"].(bool); !ok || running {
			t.Error("expected running=false")
		}
	})
}
