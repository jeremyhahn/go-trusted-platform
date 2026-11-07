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

package container

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/podman"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

func TestBuildActionsString_964(t *testing.T) {
	nm := &SDNNetworkManager{}
	tests := []struct {
		name    string
		actions []OpenFlowAction
		want    string
	}{
		{"no actions allow by default", nil, "NORMAL"},
		{"allow", []OpenFlowAction{{Type: ActionAllow}}, "NORMAL"},
		{"drop", []OpenFlowAction{{Type: ActionDrop}}, "drop"},
		{"forward to port", []OpenFlowAction{{Type: ActionForward, Port: "7"}}, "output:7"},
		{"forward without port falls back", []OpenFlowAction{{Type: ActionForward}}, "NORMAL"},
		{"unknown type falls back", []OpenFlowAction{{Type: "bogus"}}, "NORMAL"},
		{"goto table", []OpenFlowAction{{Type: ActionGoto, Table: 3}}, "resubmit(,3)"},
		{
			"actions joined in order",
			[]OpenFlowAction{{Type: ActionForward, Port: "2"}, {Type: ActionGoto, Table: 1}, {Type: ActionDrop}},
			"output:2,resubmit(,1),drop",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nm.buildActionsString(tt.actions); got != tt.want {
				t.Fatalf("buildActionsString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestImageFromProfile_964(t *testing.T) {
	tests := []struct {
		name         string
		model        string
		defaultImage string
		want         string
	}{
		{"model carries image", "container:image=quay.io/acme/app:1", "", "quay.io/acme/app:1"},
		{"model image ends at comma", "x86,container:image=quay.io/acme/app:2,arch=amd64", "", "quay.io/acme/app:2"},
		{"empty model image uses configured default", "container:image=", "registry.local/base:3", "registry.local/base:3"},
		{"no model image uses configured default", "generic", "registry.local/base:3", "registry.local/base:3"},
		{"nothing configured uses package default", "generic", "", defaultContainerImage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &ComputeOrchestrator{podmanConfig: &podman.PodmanConfig{DefaultImage: tt.defaultImage}}
			got := o.imageFromProfile(&entities.DeviceProfile{Model: tt.model})
			if got != tt.want {
				t.Fatalf("imageFromProfile() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestContainerConfigValidate_964(t *testing.T) {
	valid := func() *ContainerConfig {
		return &ContainerConfig{Name: "web-1", Image: "docker.io/library/alpine:latest"}
	}
	tests := []struct {
		name   string
		mutate func(c *ContainerConfig)
		want   error
	}{
		{"empty name", func(c *ContainerConfig) { c.Name = "" }, ErrInvalidName},
		{"malformed name", func(c *ContainerConfig) { c.Name = "bad name!" }, ErrInvalidName},
		{"empty image", func(c *ContainerConfig) { c.Image = "" }, ErrInvalidImage},
		{"invalid network mode", func(c *ContainerConfig) { c.Network.Mode = "bogus" }, ErrInvalidNetworkMode},
		{"invalid service mode", func(c *ContainerConfig) { c.Service.Mode = "bogus" }, ErrInvalidServiceMode},
		{"negative pids limit", func(c *ContainerConfig) { c.Resources.PidsLimit = -1 }, ErrInvalidResourceConfig},
		{"mount without target", func(c *ContainerConfig) { c.Mounts = []MountConfig{{Source: "/src"}} }, ErrInvalidMountConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid()
			tt.mutate(c)
			if err := c.Validate(); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("nil config", func(t *testing.T) {
		var c *ContainerConfig
		if err := c.Validate(); !errors.Is(err, ErrInvalidSpec) {
			t.Fatalf("Validate() = %v, want %v", err, ErrInvalidSpec)
		}
	})
	t.Run("valid config", func(t *testing.T) {
		if err := valid().Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})
}

func TestTypedErrors_964(t *testing.T) {
	cause := errors.New("boom")

	t.Run("message error", func(t *testing.T) {
		if got := (&MessageError{Msg: "plain"}).Error(); got != "plain" {
			t.Fatalf("Error() = %q", got)
		}
	})
	t.Run("wrapped error keeps cause", func(t *testing.T) {
		err := &WrappedError{Msg: "ctx", Err: cause}
		if err.Error() != "ctx: boom" {
			t.Fatalf("Error() = %q", err.Error())
		}
		if !errors.Is(err, cause) {
			t.Fatal("errors.Is did not reach the cause")
		}
	})
	t.Run("sentinel cause matches both", func(t *testing.T) {
		err := &SentinelCauseError{Sentinel: ErrInvalidSpec, Cause: cause}
		if err.Error() != ErrInvalidSpec.Error()+": boom" {
			t.Fatalf("Error() = %q", err.Error())
		}
		if !errors.Is(err, ErrInvalidSpec) || !errors.Is(err, cause) {
			t.Fatal("errors.Is did not match the sentinel and the cause")
		}
	})
	t.Run("resource value error", func(t *testing.T) {
		err := &ResourceValueError{Field: "cpu_limit", Value: "lots"}
		if err.Error() != "invalid resource limit cpu_limit: lots" {
			t.Fatalf("Error() = %q", err.Error())
		}
		if !errors.Is(err, ErrInvalidResourceConfig) {
			t.Fatal("errors.Is did not match ErrInvalidResourceConfig")
		}
	})
}
