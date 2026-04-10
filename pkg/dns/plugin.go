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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"

	xkmsadapter "github.com/jeremyhahn/go-trusted-platform/internal/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

const (
	trustedPlatformPlugin = "trustedPlatform"
)

// Define log to be a logger with the plugin name in it.
var (
	log = clog.NewWithPlugin(trustedPlatformPlugin)

	zoneDAO          dao.ZoneDAO
	datastoreFactory *quicbaas.Factory

	ErrInternalZoneQueryViolation = errors.New("received public query for internal zone")
)

func (cp TrustedPlatformPlugin) Name() string { return trustedPlatformPlugin }

func init() {
	plugin.Register(trustedPlatformPlugin, setup)
}

// // requestCount tracks the number of DNS queries handled by the plugin.
// var requestCount = promauto.NewCounterVec(prometheus.CounterOpts{
// 	Namespace: plugin.Namespace,
// 	Subsystem: trustedPlatformPlugin,
// 	Name:      "request_count_total",
// 	Help:      "Total number of requests handled by the custom plugin.",
// }, []string{"server"})

// TrustedPlatformPlugin is the struct implementing the plugin.Handler interface.
type TrustedPlatformPlugin struct {
	Next plugin.Handler
}

// ServeDNS handles incoming DNS requests.
func (cp TrustedPlatformPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	// Parse the port number from the local connection address
	pieces := strings.Split(w.LocalAddr().String(), ":")
	port := pieces[len(pieces)-1]

	// Parse the query name and type
	qname := dns.Fqdn(r.Question[0].Name) // Normalize the DNS name
	qtype := r.Question[0].Qtype          // Query type

	Configuration.Logger.Info("Inbound DNS query",
		slog.String("remoteAddrress", w.RemoteAddr().String()),
		slog.String("port", port),
		slog.String("qname", qname),
		slog.String("qtype", dns.TypeToString[qtype]))

	// Increment the request counter metric.
	// requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	// Validate the query
	if err := validateQuery(qname); err != nil {
		Configuration.Logger.Warn("Invalid query",
			slog.String("qname", qname),
			slog.String("error", err.Error()))
		return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)
	}

	// Locate the authoritative zone for the queried name
	zone := findZoneForQuery(ctx, qname, zoneDAO)
	if zone == nil {
		Configuration.Logger.Debug("no zone found for query", slog.String("qname", qname))
		return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)
	}

	if port == strconv.Itoa(Configuration.PublicServer.Port) && zone.Internal {

		// Reject queries for internal zones against the public server

		// Log the violation
		Configuration.Logger.Error(ErrInternalZoneQueryViolation)
		Configuration.Logger.Security(ctx, logging.SecurityLogEntry{
			Category:        logging.CategoryNetworkSecurity,
			Description:     "Ignoring public query for internal zone",
			Details:         qname,
			OffenderAddress: w.RemoteAddr().String(),
			Source:          logging.SourceDNS,
			Severity:        logging.SeverityHigh,
			Timestamp:       time.Now(),
		})

		// Don't return any kind of error or response here that an attacker
		// could use to determine the existence of internal zones.
		return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)

	}

	// Parse the queried records from the zone file
	rrs, err := parseQueriedRecord(qtype, qname, zone)
	if err != nil {
		Configuration.Logger.Error(err)
		return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)
	}

	// Send the response to the client
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Answer = append(msg.Answer, rrs...)
	if err := w.WriteMsg(&msg); err != nil {
		Configuration.Logger.Error(err)
		return dns.RcodeServerFailure, err
	}

	Configuration.Logger.Info("Query response",
		slog.String("qname", qname),
		slog.String("qtype", dns.TypeToString[qtype]),
		slog.Any("reply", rrs))

	return dns.RcodeSuccess, nil

	// Forward the request to the next plugin in the chain.
}

// findZoneForQuery locates the authoritative zone for a DNS query name by
// walking up the label hierarchy. For a query like _8443._tcp.server.example.com.,
// this tries each suffix in order:
//
//	_8443._tcp.server.example.com.
//	_tcp.server.example.com.
//	server.example.com.
//	example.com.
//	com.
//
// The first match against the zone DAO is the authoritative zone for the query.
func findZoneForQuery(ctx context.Context, qname string, zDAO dao.ZoneDAO) *entities.Zone {
	labels := dns.SplitDomainName(qname)
	for i := range labels {
		candidate := dns.Fqdn(strings.Join(labels[i:], "."))
		z, err := zDAO.Get(ctx, util.NewID([]byte(candidate)))
		if err == nil {
			return z
		}
	}
	return nil
}

func setup(c *caddy.Controller) error {
	// Parse and validate configuration from CoreDNS
	for c.Next() {
		if len(c.RemainingArgs()) > 0 {
			return plugin.Error(trustedPlatformPlugin, c.ArgErr())
		}
	}

	// Initialize macro values
	setupMacros()

	// Use injected DatastoreFactory if available (shared with main platform),
	// otherwise create a new one (standalone DNS server mode)
	if DatastoreFactory != nil {
		log.Infof("Using injected datastore factory for DNS zone storage")
		datastoreFactory = DatastoreFactory

		// Get ZoneDAO from injected factory
		var err error
		zoneDAO, err = datastoreFactory.ZoneDAO()
		if err != nil {
			return fmt.Errorf("failed to get ZoneDAO from injected factory: %w", err)
		}
	} else {
		log.Infof("Creating standalone QuicBaaS factory for DNS zone storage")

		// Create QuicBaaS factory from configuration
		factory, err := quicbaas.NewFactory(Configuration.QuicBaaS, Configuration.Logger, nil)
		if err != nil {
			return fmt.Errorf("failed to create QuicBaaS factory: %w", err)
		}
		datastoreFactory = factory

		// Start the QuicBaaS factory - required before any DAO operations
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := datastoreFactory.Start(ctx); err != nil {
			return fmt.Errorf("failed to start QuicBaaS factory: %w", err)
		}

		// Initialize global ZoneDAO defined at the top of the file and used in ServeDNS
		// to retrieve zone information
		zoneDAO, err = datastoreFactory.ZoneDAO()
		if err != nil {
			return fmt.Errorf("failed to initialize ZoneDAO: %w", err)
		}
	}

	// Process internal and public server zones
	if Configuration.InternalServer != nil {
		if err := processZone(Configuration.InternalServer.Zone, zoneDAO, "internal"); err != nil {
			return fmt.Errorf("failed to process internal zone: %w", err)
		}
	}
	if Configuration.PublicServer != nil {
		if err := processZone(Configuration.PublicServer.Zone, zoneDAO, "public"); err != nil {
			return fmt.Errorf("failed to process public zone: %w", err)
		}
	}

	// Register the plugin in the middleware chain
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return TrustedPlatformPlugin{
			Next: next,
		}
	})

	return nil
}

// isNotFoundError checks if an error is a not-found error from QuicBaaS.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Check for QuicBaaS error types
	var notFoundErr quicbaas.ErrNotFound
	if errors.As(err, &notFoundErr) {
		return true
	}
	var notFoundByIndexErr quicbaas.ErrNotFoundByIndex
	if errors.As(err, &notFoundByIndexErr) {
		return true
	}
	// Fallback: check error message for "not found"
	errMsg := err.Error()
	return strings.Contains(errMsg, "not found")
}

// processZone handles loading and saving a zone from the configuration
func processZone(zone entities.Zone, zoneDAO dao.ZoneDAO, serverType string) error {

	if zone.Name == "" {
		return fmt.Errorf("%s server zone not defined in configuration", serverType)
	}

	ctx := context.Background()

	// Check if the zone already exists in the datastore
	existingZone, err := zoneDAO.GetByName(ctx, zone.Name)
	if err != nil && !isNotFoundError(err) {
		return fmt.Errorf("failed to check if zone %s exists: %w", zone.Name, err)
	}

	// Save the zone to the datastore if it doesn't already exist
	if existingZone == nil {
		log.Infof("Zone %s (%s server) not found in datastore, saving...", zone.Name, serverType)
		if zone.ID == 0 {
			zone.ID = util.NewID([]byte(zone.Name))
		}

		// Expand config file macros
		if err := Expand(&zone); err != nil {
			return fmt.Errorf("failed to expand zone %s: %w", zone.Name, err)
		}

		// Sign the zone with DNSSEC if enabled
		if err := signZoneIfEnabled(&zone); err != nil {
			return fmt.Errorf("failed to sign zone %s: %w", zone.Name, err)
		}

		// Save the zone to the datastore
		if err := zoneDAO.Save(ctx, &zone); err != nil {
			return fmt.Errorf("failed to save zone %s: %w", zone.Name, err)
		}
		log.Infof("Zone %s (%s server) saved to datastore", zone.Name, serverType)
	} else {
		// Zone exists - check if it needs DNSSEC signing
		if needsDNSSECSigning(existingZone) {
			log.Infof("Zone %s (%s server) needs DNSSEC signing, signing...", zone.Name, serverType)

			// Sign the existing zone
			if err := signZoneIfEnabled(existingZone); err != nil {
				return fmt.Errorf("failed to sign zone %s: %w", zone.Name, err)
			}

			// Update the zone in the datastore
			if err := zoneDAO.Save(ctx, existingZone); err != nil {
				return fmt.Errorf("failed to update zone %s: %w", zone.Name, err)
			}
			log.Infof("Zone %s (%s server) DNSSEC signed and saved", zone.Name, serverType)
		}
	}

	return nil
}

// needsDNSSECSigning checks if a zone needs DNSSEC signing.
// Returns true if DNSSEC is enabled but the zone has no DNSSEC records.
func needsDNSSECSigning(zone *entities.Zone) bool {
	// Check if DNSSEC is enabled
	if Configuration == nil || Configuration.DNSSEC == nil || !Configuration.DNSSEC.Enabled {
		return false
	}

	// Check if zone already has DNSSEC records
	if len(zone.RecordSet.DNSKEYRecords) > 0 {
		// Zone already has DNSKEY records, check for RRSIG records too
		if len(zone.RecordSet.RRSIGRecords) > 0 {
			return false // Zone is already signed
		}
	}

	return true
}

// signZoneIfEnabled signs a zone with DNSSEC. DNSSEC must be configured with
// a working key backend (KeyStore or XKMSAdapter) before this is called — a
// missing backend is a hard failure, not a silent skip.
//
// Previous behaviour silently logged "skipping signing (will sign when
// available)" and returned nil, which let the caller log "Zone X DNSSEC
// signed and saved" even though the zone was NOT signed. That allowed
// zones to be persisted unsigned into the datastore with no error path,
// and the rest of the application carried on as if everything was fine.
// Removed 2026-04-08 on operator demand: no silent fallbacks, surface the
// real failure so the caller aborts.
func signZoneIfEnabled(zone *entities.Zone) error {
	if Configuration == nil || Configuration.DNSSEC == nil || !Configuration.DNSSEC.Enabled {
		return nil
	}

	var dnssecSvc *DNSSECService
	var err error

	switch {
	case KeyStore != nil:
		log.Infof("Using DNSSEC key store for key management")
		dnssecSvc, err = NewDNSSECServiceWithKeyStore(Configuration.DNSSEC, Configuration.Logger, KeyStore)
		if err != nil {
			return fmt.Errorf("dns: failed to create DNSSEC service with key store for zone %s: %w", zone.Name, err)
		}
	case XKMSAdapter != nil:
		log.Infof("Using XKMS adapter for DNSSEC key management")
		dnssecSvc, err = NewDNSSECServiceWithXKMS(Configuration.DNSSEC, Configuration.Logger, XKMSAdapter)
		if err != nil {
			return fmt.Errorf("dns: failed to create DNSSEC service with XKMS adapter for zone %s: %w", zone.Name, err)
		}
	default:
		// HARD FAIL: DNSSEC is enabled but no key backend is wired up.
		// The caller MUST NOT persist this zone as "signed" — the data is
		// unsigned and the validator will reject it downstream.
		return fmt.Errorf("dns: DNSSEC enabled for zone %s but no key store and no XKMS adapter are configured — set DNSSECKeyStore via SetDNSSECKeyStore or XKMSAdapter via SetXKMSAdapter before loading zones", zone.Name)
	}

	log.Infof("Signing zone %s with DNSSEC", zone.Name)
	if err := dnssecSvc.SignZone(zone); err != nil {
		return fmt.Errorf("dns: DNSSEC signing failed for zone %s: %w", zone.Name, err)
	}
	log.Infof("Zone %s signed with DNSSEC successfully", zone.Name)

	return nil
}

// SetXKMSAdapter sets the global XKMS adapter for DNSSEC key management
// and signs any zones that were loaded before the adapter was available.
func SetXKMSAdapter(adapter *xkmsadapter.Adapter) error {
	XKMSAdapter = adapter
	return SignUnsignedZones()
}

// SetDNSSECKeyStore sets the global DNSSEC key store and signs any zones
// that were loaded before the key store was available.
func SetDNSSECKeyStore(ks DNSSECKeyStore) error {
	KeyStore = ks
	return SignUnsignedZones()
}

// SignUnsignedZones signs all zones that need DNSSEC signing.
// This is called after the XKMS adapter or key store becomes available
// to handle deferred signing from initial zone loading.
func SignUnsignedZones() error {
	if Configuration == nil || Configuration.DNSSEC == nil || !Configuration.DNSSEC.Enabled {
		return nil
	}

	if KeyStore == nil && XKMSAdapter == nil {
		return nil
	}

	if zoneDAO == nil {
		return nil
	}

	ctx := context.Background()

	// Collect zones that need signing from the configured servers
	type zoneRef struct {
		name       string
		serverType string
	}
	var zones []zoneRef

	if Configuration.InternalServer != nil && Configuration.InternalServer.Zone.Name != "" {
		zones = append(zones, zoneRef{
			name:       Configuration.InternalServer.Zone.Name,
			serverType: "internal",
		})
	}
	if Configuration.PublicServer != nil && Configuration.PublicServer.Zone.Name != "" {
		zones = append(zones, zoneRef{
			name:       Configuration.PublicServer.Zone.Name,
			serverType: "public",
		})
	}

	for _, zr := range zones {
		zone, err := zoneDAO.GetByName(ctx, zr.name)
		if err != nil {
			log.Warningf("Failed to retrieve zone %s for deferred DNSSEC signing: %v", zr.name, err)
			continue
		}
		if zone == nil {
			continue
		}

		if !needsDNSSECSigning(zone) {
			continue
		}

		log.Infof("Deferred DNSSEC signing for zone %s (%s server)", zr.name, zr.serverType)

		if err := signZoneIfEnabled(zone); err != nil {
			log.Warningf("Failed deferred DNSSEC signing for zone %s: %v", zr.name, err)
			continue
		}

		if err := zoneDAO.Save(ctx, zone); err != nil {
			log.Warningf("Failed to save zone %s after deferred DNSSEC signing: %v", zr.name, err)
			continue
		}

		log.Infof("Zone %s (%s server) DNSSEC signed via deferred signing", zr.name, zr.serverType)
	}

	return nil
}

// Saves a new zone file to the datastore. If DNSSEC is enabled, the zone
// is signed before saving. This function uses the global zoneDAO that's
// initialized during plugin setup.
func Save(ctx context.Context, zone *entities.Zone) error {
	if zoneDAO == nil {
		return fmt.Errorf("zone DAO not initialized - plugin setup may not have completed")
	}

	if zone.ID == 0 {
		zone.ID = util.NewID([]byte(zone.Name))
	}

	// Sign the zone with DNSSEC if enabled
	if err := signZoneIfEnabled(zone); err != nil {
		return fmt.Errorf("failed to sign zone: %w", err)
	}

	if err := zoneDAO.Save(ctx, zone); err != nil {
		return fmt.Errorf("failed to save zone: %w", err)
	}

	return nil
}

// Helper functions to handle pointer fields
func uint16Ptr(i uint16) *uint16 { return &i }
func uint32Ptr(i uint32) *uint32 { return &i }
