package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"

	aferodao "github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao/afero"
)

const (
	trustedPlatformPlugin = "trustedPlatform"
)

// Define log to be a logger with the plugin name in it.
var (
	log = clog.NewWithPlugin(trustedPlatformPlugin)

	zoneDAO      dao.ZoneDAO
	dsZoneParams *datastore.Params[*entities.Zone]

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

// once ensures metrics are registered only once.
var once sync.Once

// TrustedPlatformPlugin is the struct implementing the plugin.Handler interface.
type TrustedPlatformPlugin struct {
	Next plugin.Handler
}

type SecurityLogEntry struct {
	Timestamp       time.Time `json:"timestamp"`
	Severity        string    `json:"severity"`
	Category        string    `json:"category"`
	Description     string    `json:"description"`
	Details         string    `json:"details,omitempty"`
	Source          string    `json:"source,omitempty"`
	OffenderAddress string    `json:"offender_address,omitempty"`
	OffenderID      string    `json:"offender_id,omitempty"`
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
		slog.String("address", w.LocalAddr().String()),
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

	// First try to locate the zone using the qname
	var zone *entities.Zone
	var err error

	zone, err = zoneDAO.Get(util.NewID([]byte(qname)), dsZoneParams.ConsistencyLevel)
	if err != nil {

		// Not found; parse the query into zone, subomain and record name
		_, subdomains, zoneName, _, err := ParseDomainName(qname)
		if err != nil {
			Configuration.Logger.Error(err)
			return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)
		}

		// Try to locate the query as a subdomain
		if subdomains != "" {
			zoneName = fmt.Sprintf("%s.%s", subdomains, zoneName)
		}
		zoneName = fmt.Sprintf("%s.", zoneName)

		zone, err = zoneDAO.Get(util.NewID([]byte(zoneName)), dsZoneParams.ConsistencyLevel)
		if err != nil {
			Configuration.Logger.Error(err)
			return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)
		}
	}

	if port == strconv.Itoa(Configuration.PublicServer.Port) && zone.Internal {

		// Reject queries for internal zones against the public server

		// Log the violation
		Configuration.Logger.Error(ErrInternalZoneQueryViolation)
		Configuration.Logger.Security(logging.SecurityLogEntry{
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

func setup(c *caddy.Controller) error {

	var err error

	// Parse and validate configuration from CoreDNS
	for c.Next() {
		if len(c.RemainingArgs()) > 0 {
			return plugin.Error(trustedPlatformPlugin, c.ArgErr())
		}
	}

	// Initialize macro values
	setupMacros()

	// Retrieve datastore parameters abd set the dsZoneParams global variable
	// for use in ServeDNS
	dsZoneParams, err = datastore.ParamsFromConfig[*entities.Zone](Configuration.Datastore, "dns/zones")
	if err != nil {
		return fmt.Errorf("failed to create datastore parameters: %w", err)
	}

	// Initialize global ZoneDAO defined at the top of the file and used in ServeDNS
	// to retrieve zone information
	zoneDAO, err = aferodao.NewZoneDAO(dsZoneParams)
	if err != nil {
		return fmt.Errorf("failed to initialize ZoneDAO: %w", err)
	}

	// Process internal and public server zones
	if err := processZone(Configuration.InternalServer.Zone, zoneDAO, "internal"); err != nil {
		return fmt.Errorf("failed to process internal zone: %w", err)
	}
	if err := processZone(Configuration.PublicServer.Zone, zoneDAO, "public"); err != nil {
		return fmt.Errorf("failed to process public zone: %w", err)
	}

	// Register the plugin in the middleware chain
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return TrustedPlatformPlugin{
			Next: next,
		}
	})

	return nil
}

// processZone handles loading and saving a zone from the configuration
func processZone(zone entities.Zone, zoneDAO dao.ZoneDAO, serverType string) error {

	if zone.Name == "" {
		return fmt.Errorf("%s server zone not defined in configuration", serverType)
	}

	// Set the datastore read consistency level
	consistencyLevel := datastore.ParseConsistentLevel(Configuration.Datastore.ConsistencyLevel)

	// Check if the zone already exists in the datastore
	existingZone, err := zoneDAO.GetByName(zone.Name, consistencyLevel)
	if err != nil && !errors.Is(err, datastore.ErrRecordNotFound) {
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

		// Save the zone to the datastore
		if err := zoneDAO.Save(&zone); err != nil {
			return fmt.Errorf("failed to save zone %s: %w", zone.Name, err)
		}
		log.Infof("Zone %s (%s server) saved to datastore", zone.Name, serverType)
	}

	return nil
}

// Saves a new zone file to the datastore
func Save(zone *entities.Zone) error {

	if zone.ID == 0 {
		zone.ID = util.NewID([]byte(zone.Name))
	}

	params, err := datastore.ParamsFromConfig[*entities.Zone](
		Configuration.Datastore, DatastorePartition)
	if err != nil {
		fmt.Println("Error creating Params:", err)
		return err
	}

	dao, err := aferodao.NewZoneDAO(params)
	if err != nil {
		fmt.Println("Error creating ZoneDAO:", err)
		return err
	}

	if err := dao.Save(zone); err != nil {
		fmt.Println("Error saving zone:", err)
		return err
	}

	return nil
}

// Helper functions to handle pointer fields
func uint16Ptr(i uint16) *uint16 { return &i }
func uint32Ptr(i uint32) *uint32 { return &i }
