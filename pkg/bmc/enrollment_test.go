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
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultEnrollmentConfig(t *testing.T) {
	cfg := DefaultEnrollmentConfig()
	if cfg == nil {
		t.Fatal("DefaultEnrollmentConfig returned nil")
	}
	if cfg.Auto {
		t.Error("Auto should default to false")
	}
	if !cfg.ReplaceCertificate {
		t.Error("ReplaceCertificate should default to true")
	}
	if !cfg.Backup {
		t.Error("Backup should default to true")
	}
	if cfg.RotatePassword {
		t.Error("RotatePassword should default to false")
	}
	if !cfg.DNSRegister {
		t.Error("DNSRegister should default to true")
	}
	if !cfg.DANEPublish {
		t.Error("DANEPublish should default to true")
	}
}

func TestEnrollmentConfig_YAMLRoundTrip(t *testing.T) {
	original := &EnrollmentConfig{
		Auto:               true,
		ReplaceCertificate: false,
		Backup:             false,
		RotatePassword:     true,
		DNSRegister:        false,
		DANEPublish:        false,
	}

	data, err := yaml.Marshal(original)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}

	var decoded EnrollmentConfig
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	if decoded.Auto != original.Auto {
		t.Errorf("Auto: got %v, want %v", decoded.Auto, original.Auto)
	}
	if decoded.ReplaceCertificate != original.ReplaceCertificate {
		t.Errorf("ReplaceCertificate: got %v, want %v", decoded.ReplaceCertificate, original.ReplaceCertificate)
	}
	if decoded.Backup != original.Backup {
		t.Errorf("Backup: got %v, want %v", decoded.Backup, original.Backup)
	}
	if decoded.RotatePassword != original.RotatePassword {
		t.Errorf("RotatePassword: got %v, want %v", decoded.RotatePassword, original.RotatePassword)
	}
	if decoded.DNSRegister != original.DNSRegister {
		t.Errorf("DNSRegister: got %v, want %v", decoded.DNSRegister, original.DNSRegister)
	}
	if decoded.DANEPublish != original.DANEPublish {
		t.Errorf("DANEPublish: got %v, want %v", decoded.DANEPublish, original.DANEPublish)
	}
}

func TestConfigEnrollmentField_EmbeddingRoundTrip(t *testing.T) {
	const input = `
address: "192.168.1.10"
port: 623
protocol: ipmi
username: admin
password: secret
enrollment:
  auto: false
  replace-certificate: true
  backup: true
  rotate-password: false
  dns-register: true
  dane-publish: false
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if cfg.Enrollment == nil {
		t.Fatal("Enrollment is nil after unmarshal")
	}
	if cfg.Enrollment.Auto {
		t.Error("Auto should be false")
	}
	if !cfg.Enrollment.ReplaceCertificate {
		t.Error("ReplaceCertificate should be true")
	}
	if !cfg.Enrollment.Backup {
		t.Error("Backup should be true")
	}
	if cfg.Enrollment.RotatePassword {
		t.Error("RotatePassword should be false")
	}
	if !cfg.Enrollment.DNSRegister {
		t.Error("DNSRegister should be true")
	}
	if cfg.Enrollment.DANEPublish {
		t.Error("DANEPublish should be false")
	}
}

func TestConfig_EffectiveEnrollment_NilFallback(t *testing.T) {
	cfg := &Config{}
	eff := cfg.effectiveEnrollment()
	if eff == nil {
		t.Fatal("effectiveEnrollment returned nil")
	}
	// Should match defaults when Enrollment is nil.
	def := DefaultEnrollmentConfig()
	if eff.Auto != def.Auto ||
		eff.ReplaceCertificate != def.ReplaceCertificate ||
		eff.Backup != def.Backup ||
		eff.RotatePassword != def.RotatePassword ||
		eff.DNSRegister != def.DNSRegister ||
		eff.DANEPublish != def.DANEPublish {
		t.Error("effectiveEnrollment did not return defaults when Enrollment is nil")
	}
}

func TestConfig_EffectiveEnrollment_UsesExplicit(t *testing.T) {
	explicit := &EnrollmentConfig{
		Auto:               true,
		ReplaceCertificate: false,
		Backup:             false,
		RotatePassword:     true,
		DNSRegister:        false,
		DANEPublish:        false,
	}
	cfg := &Config{Enrollment: explicit}
	eff := cfg.effectiveEnrollment()
	if eff != explicit {
		t.Error("effectiveEnrollment should return the explicit config when set")
	}
}
