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

package bootstrap

import (
	"errors"
	"reflect"
	"slices"
	"testing"
)

type secretFieldsCredentials struct {
	User     string `yaml:"user"`
	Password string `yaml:"password" secret:"true"`
}

type secretFieldsCommon struct {
	Token string `yaml:"token" secret:"true"`
}

type secretFieldsSquashed struct {
	APIKey string `mapstructure:"api-key" secret:"true"`
}

type secretFieldsSchema struct {
	secretFieldsCommon `yaml:",inline"`
	Squashed           secretFieldsSquashed               `mapstructure:",squash"`
	Name               string                             `yaml:"name"`
	PIN                string                             `yaml:"so-pin" mapstructure:"so-pin" secret:"true"`
	BMC                *secretFieldsCredentials           `yaml:"bmc"`
	Switches           []secretFieldsCredentials          `yaml:"switches"`
	Zones              map[string]secretFieldsCredentials `yaml:"zones"`
	Keys               []string                           `yaml:"keys" secret:"true"`
}

func TestPlaintextSecretFields_ReportsEachLiteral(t *testing.T) {
	doc := []byte(`
name: node-1
token: literal-token
api-key: literal-api-key
so-pin: "12345678"
bmc:
  user: admin
  password: hunter2
switches:
  - user: a
    password: kms://switch-0
  - user: b
    password: switch-literal
zones:
  example.com:
    password: zone-literal
keys:
  - kms://k0
  - literal-key
unknown:
  password: not-in-schema
`)
	got, err := PlaintextSecretFields(doc, reflect.TypeFor[secretFieldsSchema]())
	if err != nil {
		t.Fatalf("PlaintextSecretFields: %v", err)
	}
	want := []string{
		"token",
		"api-key",
		"so-pin",
		"bmc.password",
		"switches[1].password",
		"zones.example.com.password",
		"keys",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPlaintextSecretFields_ReferencesAndEmptyValuesPass(t *testing.T) {
	doc := []byte(`
name: node-1
token: env://TOKEN
so-pin: kms://platform/so-pin
bmc:
  user: admin
  password: ""
switches:
  - password: ~
  - password: file:///run/secrets/switch
keys: []
`)
	got, err := PlaintextSecretFields(doc, reflect.TypeFor[*secretFieldsSchema]())
	if err != nil {
		t.Fatalf("PlaintextSecretFields: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q, want none", got)
	}
}

func TestPlaintextSecretFields_MatchesKeysCaseInsensitively(t *testing.T) {
	got, err := PlaintextSecretFields([]byte("BMC:\n  Password: hunter2\n"), reflect.TypeFor[secretFieldsSchema]())
	if err != nil {
		t.Fatalf("PlaintextSecretFields: %v", err)
	}
	if !slices.Equal(got, []string{"BMC.Password"}) {
		t.Fatalf("got %q, want [BMC.Password]", got)
	}
}

func TestPlaintextSecretFields_FollowsAnchorsAndMergeKeys(t *testing.T) {
	doc := []byte(`
defaults: &creds
  password: merged-literal
bmc:
  <<: *creds
  user: admin
so-pin: &pin "12345678"
token: *pin
`)
	got, err := PlaintextSecretFields(doc, reflect.TypeFor[secretFieldsSchema]())
	if err != nil {
		t.Fatalf("PlaintextSecretFields: %v", err)
	}
	want := []string{"bmc.password", "so-pin", "token"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPlaintextSecretFields_SelfReferencingAnchorEnds(t *testing.T) {
	got, err := PlaintextSecretFields([]byte("keys: &k [*k]\n"), reflect.TypeFor[secretFieldsSchema]())
	if err != nil {
		t.Fatalf("PlaintextSecretFields: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q, want none", got)
	}
}

func TestPlaintextSecretFields_EmptyDocumentHasNone(t *testing.T) {
	got, err := PlaintextSecretFields(nil, reflect.TypeFor[secretFieldsSchema]())
	if err != nil {
		t.Fatalf("PlaintextSecretFields: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q, want none", got)
	}
}

func TestPlaintextSecretFields_RejectsMalformedYAML(t *testing.T) {
	_, err := PlaintextSecretFields([]byte("bmc: [unclosed\n"), reflect.TypeFor[secretFieldsSchema]())
	var parseErr ErrSecretDocumentParse
	if !errors.As(err, &parseErr) {
		t.Fatalf("got %v, want ErrSecretDocumentParse", err)
	}
	if parseErr.Unwrap() == nil {
		t.Fatal("ErrSecretDocumentParse carries no cause")
	}
}

func TestPlaintextSecretFields_RejectsNonStructSchema(t *testing.T) {
	for _, schema := range []reflect.Type{nil, reflect.TypeFor[string](), reflect.TypeFor[map[string]string]()} {
		_, err := PlaintextSecretFields([]byte("a: b\n"), schema)
		var schemaErr ErrSecretSchemaNotStruct
		if !errors.As(err, &schemaErr) {
			t.Fatalf("schema %v: got %v, want ErrSecretSchemaNotStruct", schema, err)
		}
	}
}
