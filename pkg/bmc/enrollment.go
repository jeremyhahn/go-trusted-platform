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

// EnrollmentConfig controls which optional steps the BMC enrollment ceremony
// performs. The default (via DefaultEnrollmentConfig) enables certificate
// replacement and DNS/DANE registration but skips automatic triggering and
// password rotation, following the principle of least-surprise for operators
// who invoke enrollment manually.
//
// Fields correspond directly to the per-BMC YAML enrollment block:
//
//	enrollment:
//	  auto: false
//	  replace-certificate: true
//	  backup: true
//	  rotate-password: false
//	  dns-register: true
//	  dane-publish: true
type EnrollmentConfig struct {
	// Auto, when true, triggers enrollment automatically on first BMC contact
	// without requiring an explicit operator call. Defaults to false — operators
	// must opt in to unsupervised enrollment.
	Auto bool `yaml:"auto" json:"auto" mapstructure:"auto"`

	// ReplaceCertificate, when true, replaces the BMC's factory TLS certificate
	// with a platform-issued certificate during enrollment. Defaults to true.
	ReplaceCertificate bool `yaml:"replace-certificate" json:"replace_certificate" mapstructure:"replace-certificate"`

	// Backup, when true, captures the factory certificate before replacement so
	// operators can restore the original state. Defaults to true.
	Backup bool `yaml:"backup" json:"backup" mapstructure:"backup"`

	// RotatePassword, when true, generates and persists a new BMC admin password
	// during enrollment. Defaults to false — password rotation is a disruptive
	// operation and should be opted into explicitly.
	RotatePassword bool `yaml:"rotate-password" json:"rotate_password" mapstructure:"rotate-password"`

	// DNSRegister, when true, creates an A record for the BMC endpoint in the
	// platform's internal DNS zone as <hostname>-bmc.<zone>. Defaults to true.
	DNSRegister bool `yaml:"dns-register" json:"dns_register" mapstructure:"dns-register"`

	// DANEPublish, when true, publishes DANE TLSA records for the BMC's TLS
	// certificate so Strict DANE clients can verify it without a public CA.
	// Requires ReplaceCertificate and DNSRegister. Defaults to true.
	DANEPublish bool `yaml:"dane-publish" json:"dane_publish" mapstructure:"dane-publish"`
}

// DefaultEnrollmentConfig returns an EnrollmentConfig with conservative
// production defaults: certificate replacement, backup, and DNS+DANE
// registration are enabled; automatic triggering and password rotation are
// disabled.
func DefaultEnrollmentConfig() *EnrollmentConfig {
	return &EnrollmentConfig{
		Auto:               false,
		ReplaceCertificate: true,
		Backup:             true,
		RotatePassword:     false,
		DNSRegister:        true,
		DANEPublish:        true,
	}
}
