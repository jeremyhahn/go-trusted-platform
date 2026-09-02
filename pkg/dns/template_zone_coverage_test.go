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

package dns

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The shipped device templates issue the control plane's webservice
// certificates for names the control plane's OWN authoritative zones must
// answer for: every client node points acme.client.directory at
// https://cp.<internal-domain>:9443/... and then verifies the TLS handshake
// against that certificate's SANs. A name that appears in a certificate but
// not in the zone breaks enrolment at resolution, and respelling the URL to a
// name the zone does serve breaks it one step later at SAN validation instead.
//
// This test asserts that invariant: for every webservice certificate name
// that falls inside a zone the template ships, that zone serves a record that
// answers it WITH THE RIGHT ADDRESS.
//
// It deliberately does NOT resolve through recordParserFuncs. That parser
// matches an A record on the query's FIRST LABEL ONLY (parser.go:42-49), so
// it answers www.cp.example.com from a record named `www` — a name nothing
// declares, at whatever address `www` happens to point to. A test built on it
// conflates the two names and passes while the SAN is still unserved. The
// rule below is the strict one the parser approximates: a name is served only
// as the zone apex via `@`, or as a single label directly beneath it.
//
// A corollary worth knowing before "fixing" a gap this test reports: because
// matching is first-label-only, a record named `www.cp` — or the FQDN form —
// can never match any query. Spelling a nested name into a zone produces
// config that looks correct and never answers.
//
// Regression guard for #77, where dns.internal.zone shipped only @, ns1 and
// ${HOSTNAME} while the internal webservice was issued CN=cp.<internal-domain>
// with that as its only SAN.

// templateFile is the slice of a device template this test reads. Only the
// two sections that have to agree are modelled.
type templateFile struct {
	DNS         Config           `yaml:"dns"`
	Webservices []templateWebSvc `yaml:"webservices"`
}

type templateWebSvc struct {
	Name        string `yaml:"name"`
	Certificate struct {
		Subject struct {
			CommonName string `yaml:"cn"`
		} `yaml:"subject"`
		SANS struct {
			DNS []string `yaml:"dns"`
		} `yaml:"sans"`
	} `yaml:"certificate"`
}

func TestShippedTemplateZonesServeTheirCertificateNames(t *testing.T) {
	// Certificate names the shipped zones knowingly do NOT serve, pinned so
	// the gap can neither grow unnoticed nor be papered over with a record
	// that cannot match.
	//
	// www.cp.example.com is a SAN on the public webservice certificate. The
	// public zone's apex is example.com., so the name sits two labels below
	// it and no record spelling can answer it (see the file comment). Making
	// it resolve means moving the zone origin to cp.example.com. — which is
	// what this template's SOA name, NS records, MX/TXT owners, zone
	// description, top-level `domain:` key, WebAuthn relying-party-id and
	// certificate subject all already say. That changes what the control
	// plane claims public authority for, so it is an owner call (#77) and is
	// not made here. Today the name silently resolves to whatever the `www`
	// record points at.
	knownUnserved := map[string]bool{
		"www.cp.example.com.": true,
	}

	templates := []string{
		"dedicated/supermicro/x10/control-plane.yaml",
		"dedicated/dell/r640/control-plane.yaml",
		"single-node/default.yaml",
	}

	for _, rel := range templates {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			path := filepath.Join("..", "..", "configs", "platform", "templates", rel)
			raw, err := os.ReadFile(path)
			require.NoError(t, err, "read template %s", path)

			var tpl templateFile
			require.NoError(t, yaml.Unmarshal(raw, &tpl), "parse template %s", path)

			// Expand ${PRIVATE_IPv4} / ${PUBLIC_IPv4} / ${HOSTNAME} the same
			// way processZone does before a zone is persisted. Without this
			// every A record name is a literal macro and ${HOSTNAME} would
			// never match anything.
			macros["PRIVATE_IPv4"] = testPrivateIPv4
			macros["PUBLIC_IPv4"] = testPublicIPv4
			macros["HOSTNAME"] = "cp01"

			// Each zone carries the address its records must resolve to. An
			// internal name answering the public address (or the reverse)
			// sends clients at the wrong interface, which is a live defect
			// and not merely a cosmetic one, so the expectation travels with
			// the zone rather than being checked by eye.
			zones := make([]*checkedZone, 0, 2)
			if tpl.DNS.InternalServer != nil {
				zones = append(zones, &checkedZone{
					zone: &tpl.DNS.InternalServer.Zone,
					kind: "internal", wantIP: testPrivateIPv4,
				})
			}
			if tpl.DNS.PublicServer != nil {
				zones = append(zones, &checkedZone{
					zone: &tpl.DNS.PublicServer.Zone,
					kind: "public", wantIP: testPublicIPv4,
				})
			}
			require.NotEmpty(t, zones, "%s ships no authoritative zone", rel)

			for _, cz := range zones {
				z := cz.zone
				require.NotEmpty(t, z.Name, "zone in %s has no name", rel)
				require.True(t, strings.HasSuffix(z.Name, "."),
					"zone %q in %s must be fully qualified: processZone hashes "+
						"zone.Name verbatim while findZoneForQuery hashes the "+
						"FQDN, so a missing trailing dot makes the zone "+
						"unreachable", z.Name, rel)
				require.NoError(t, Expand(z), "expand macros in zone %s", z.Name)

				// An A record owner is a single label relative to the apex,
				// or "@". A dotted owner (www.cp, or a full FQDN) can never
				// match: parser.go compares against the query's first label
				// alone. Such a record reads as a fix and answers nothing.
				for _, r := range z.RecordSet.ARecords {
					require.NotContains(t, r.Name, ".",
						"zone %q in %s declares A record %q with a dotted "+
							"owner. pkg/dns/parser.go matches on the query's "+
							"first label only, so this record can never "+
							"answer; the name it is meant to serve is instead "+
							"answered by whatever record shares its leftmost "+
							"label", z.Name, rel, r.Name)
				}
			}

			require.NotEmpty(t, tpl.Webservices, "%s declares no webservices", rel)

			checked := 0
			unserved := map[string]string{}
			for _, ws := range tpl.Webservices {
				names := append([]string{}, ws.Certificate.SANS.DNS...)
				if cn := ws.Certificate.Subject.CommonName; cn != "" {
					names = append(names, cn)
				}
				for _, name := range names {
					fqdn := dns.Fqdn(strings.ToLower(name))

					cz := zoneFor(zones, fqdn)
					if cz == nil {
						// Issued for a name this node is not authoritative
						// for (a public CA's domain, say). Resolution is
						// somebody else's zone; nothing to assert here.
						continue
					}
					checked++

					if rec := servedBy(cz.zone, fqdn); rec != nil {
						require.False(t, knownUnserved[fqdn],
							"%s: %q is pinned as knowingly unserved but zone %q "+
								"now answers it — the gap was closed, so remove "+
								"it from knownUnserved",
							rel, name, cz.zone.Name)

						// Resolving is not enough: it has to resolve to the
						// right network. A cert name in the internal zone
						// answering the public address points every client
						// at an interface the control plane does not serve
						// this certificate on.
						require.Equal(t, cz.wantIP, rec.Value,
							"%s: %q resolves in the %s zone %q via record %q, "+
								"but to %s instead of %s. A name that answers "+
								"with the wrong address is worse than one that "+
								"does not answer: enrolment fails at connect "+
								"or TLS rather than at DNS, where the cause is "+
								"visible.",
							rel, name, cz.kind, cz.zone.Name, rec.Name,
							rec.Value, cz.wantIP)
						continue
					}
					if knownUnserved[fqdn] {
						continue
					}
					unserved[fqdn] = fmt.Sprintf(
						"webservice %q is issued a certificate for %q, but zone "+
							"%q serves no record that answers it (A records: %s)",
						ws.Name, name, cz.zone.Name, aRecordNames(cz.zone))
				}
			}

			require.Empty(t, unserved,
				"%s: certificate names the shipped zone cannot answer. Clients "+
					"that read these out of the certificate, or out of an ACME "+
					"directory URL, get no answer: %v", rel, unserved)

			require.NotZero(t, checked,
				"%s: no certificate name fell inside a shipped zone — the test "+
					"asserted nothing, which means the template shape changed",
				rel)
		})
	}
}

// Addresses the templates' ${PRIVATE_IPv4} / ${PUBLIC_IPv4} macros expand to
// for the purposes of this test. They must differ, so that a record pointing
// at the wrong network is detectable at all.
const (
	testPrivateIPv4 = "10.0.0.10"
	testPublicIPv4  = "203.0.113.10"
)

// checkedZone pairs a shipped zone with the address its records are required
// to resolve to.
type checkedZone struct {
	zone   *entities.Zone
	kind   string
	wantIP string
}

// servedBy returns the A record that answers fqdn in zone, or nil. A zone
// serves its own apex through an "@" record and serves exactly one label
// beneath the apex through a record of that label. Anything deeper is
// unserveable: pkg/dns/parser.go matches on the query's first label alone, so
// a record naming a deeper owner never matches, and the query is instead
// answered by whatever record shares its leftmost label.
//
// It returns the record rather than a bool so the caller can assert the
// address as well as the owner. Matching the owner alone would accept a record
// that resolves the right name to the wrong network.
func servedBy(zone *entities.Zone, fqdn string) *entities.ARecord {
	label := "@"
	if fqdn != zone.Name {
		rest := strings.TrimSuffix(fqdn, "."+strings.TrimSuffix(zone.Name, ".")+".")
		if rest == fqdn || strings.Contains(rest, ".") {
			// Not directly beneath this apex.
			return nil
		}
		label = rest
	}
	for _, r := range zone.RecordSet.ARecords {
		if r.Name == label {
			return r
		}
	}
	return nil
}

// zoneFor returns the shipped zone authoritative for fqdn, or nil.
func zoneFor(zones []*checkedZone, fqdn string) *checkedZone {
	var best *checkedZone
	for _, cz := range zones {
		z := cz.zone
		if fqdn == z.Name || strings.HasSuffix(fqdn, "."+strings.TrimSuffix(z.Name, ".")+".") {
			if best == nil || len(z.Name) > len(best.zone.Name) {
				best = cz
			}
		}
	}
	return best
}

// TestServedByDistinguishesAddress is the negative half of the guard above:
// it proves the address assertion can actually fail. Without it, matching the
// owner label alone would accept an internal name answering the public
// address, which is the swap the templates make easy — the two zones differ
// only in which macro their records carry.
func TestServedByDistinguishesAddress(t *testing.T) {
	internal := &entities.Zone{
		Name: "example.internal.",
		RecordSet: entities.RecordSet{ARecords: []*entities.ARecord{
			{Name: "@", Value: testPrivateIPv4},
			{Name: "cp", Value: testPublicIPv4}, // swapped: the defect
		}},
	}
	public := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{ARecords: []*entities.ARecord{
			{Name: "@", Value: testPublicIPv4},
			{Name: "cp", Value: testPrivateIPv4}, // swapped: the defect
		}},
	}

	rec := servedBy(internal, "cp.example.internal.")
	require.NotNil(t, rec, "owner must still match — the swap is in the value")
	require.NotEqual(t, testPrivateIPv4, rec.Value,
		"a swapped internal record must be distinguishable from a correct one")

	rec = servedBy(public, "cp.example.com.")
	require.NotNil(t, rec)
	require.NotEqual(t, testPublicIPv4, rec.Value,
		"a swapped public record must be distinguishable from a correct one")

	// And the correct case is accepted, so the check is not simply always-fail.
	good := &entities.Zone{
		Name: "example.internal.",
		RecordSet: entities.RecordSet{ARecords: []*entities.ARecord{
			{Name: "cp", Value: testPrivateIPv4},
		}},
	}
	rec = servedBy(good, "cp.example.internal.")
	require.NotNil(t, rec)
	require.Equal(t, testPrivateIPv4, rec.Value)

	// A name two labels below the apex is not served by any record spelling.
	require.Nil(t, servedBy(public, "www.cp.example.com."),
		"a name two labels below the apex must report unserved, not match the "+
			"record sharing its leftmost label")
}

func aRecordNames(z *entities.Zone) string {
	names := make([]string, 0, len(z.RecordSet.ARecords))
	for _, r := range z.RecordSet.ARecords {
		names = append(names, r.Name)
	}
	return strings.Join(names, ", ")
}
