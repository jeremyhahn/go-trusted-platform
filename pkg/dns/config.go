package dns

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

var (
	DatastorePartition = "dns/zones"

	Configuration *Config

	DefaultConfig = Config{
		Datastore: &datastore.Config{
			Backend:          "AFERO_FS",
			ConsistencyLevel: "local",
			RootDir:          "trusted-data/datastore",
			ReadBufferSize:   50,
			Serializer:       "json",
		},
		PublicServer: &PublicServer{
			Port:       8053,
			Forwarders: []string{"4.4.4.4", "8.8.8.8"},
			Zone: entities.Zone{
				ID:          1,
				Name:        "trusted-platform.io.",
				TTL:         3600,
				Description: "Public zone for trusted-platform.io",
				Internal:    false,
				RecordSet: entities.RecordSet{
					SOARecord: entities.SOARecord{
						Name:       "trusted-platform.io.",
						MName:      "ns1.trusted-platform.io.",
						RName:      "hostmaster.trusted-platform.io.",
						Serial:     1,
						Refresh:    86400,
						Retry:      7200,
						Expire:     86400,
						MinimumTTL: 3600,
						TTL:        3600,
					},
					NSRecords: []*entities.NSRecord{
						{Name: "trusted-platform.io.", Value: "ns1.trusted-platform.io.", TTL: 3600},
						{Name: "trusted-platform.io.", Value: "ns2.trusted-platform.io.", TTL: 3600},
						{Name: "trusted-platform.io.", Value: "ns3.trusted-platform.io.", TTL: 3600},
					},
					ARecords: []*entities.ARecord{
						{Name: "ns1", Value: "${PUBLIC_IPv4}", TTL: 3600},
						{Name: "ns2", Value: "${PUBLIC_IPv4}", TTL: 3600},
						{Name: "ns3", Value: "${PUBLIC_IPv4}", TTL: 3600},
						{Name: "www", Value: "${PUBLIC_IPv4}", TTL: 3600},
					},
					CNAMERecords: []*entities.CNAMERecord{
						{Name: "www", Value: "trusted-platform.io.", TTL: 3600},
					},
					MXRecords: []*entities.MXRecord{
						{Name: "trusted-platform.io.", Value: "mail.trusted-platform.io.", Priority: 10, TTL: 3600},
					},
					TXTRecords: []*entities.TXTRecord{
						{Name: "trusted-platform.io.", Value: "v=spf1 include:_spf.google.com ~all", TTL: 3600},
					},
				},
			},
		},
		InternalServer: &InternalServer{
			Port:       8054,
			Forwarders: []string{"192.168.1.1", "192.168.2.1", "192.168.3.1"},
			Zone: entities.Zone{
				ID:          2,
				Name:        "trusted-platform.internal.",
				TTL:         3600,
				Description: "Internal zone for trusted-platform.internal",
				Internal:    true,
				RecordSet: entities.RecordSet{
					SOARecord: entities.SOARecord{
						Name:       "trusted-platform.internal.",
						MName:      "ns1.trusted-platform.internal.",
						RName:      "hostmaster.trusted-platform.internal.",
						Serial:     1,
						Refresh:    86400,
						Retry:      7200,
						Expire:     86400,
						MinimumTTL: 3600,
						TTL:        3600,
					},
					NSRecords: []*entities.NSRecord{
						{Name: "trusted-platform.internal.", Value: "ns1.trusted-platform.internal.", TTL: 3600},
						{Name: "trusted-platform.internal.", Value: "ns2.trusted-platform.internal.", TTL: 3600},
						{Name: "trusted-platform.internal.", Value: "ns3.trusted-platform.internal.", TTL: 3600},
					},
					ARecords: []*entities.ARecord{
						{Name: "ns1", Value: "${LOCAL_IPv4}", TTL: 3600},
						{Name: "ns2", Value: "192.168.2.1", TTL: 3600},
						{Name: "ns3", Value: "192.168.3.1", TTL: 3600},
						{Name: "${HOSTNAME}", Value: "${LOCAL_IPv4}", TTL: 3600},
					},
					CNAMERecords: []*entities.CNAMERecord{
						{Name: "www", Value: "trusted-platform.internal.", TTL: 3600},
					},
				},
			},
		},
	}
)

type Config struct {
	AllowRegistration         bool              `yaml:"allow-registration" json:"allow_registration" mapstructure:"allow-registration"`
	AllowExternalRegistration bool              `yaml:"allow-external-registration" json:"allow_external_registration" mapstructure:"allow-external-registration"`
	AllowInternalRegistration bool              `yaml:"allow-internal-registration" json:"allow_internal_registration" mapstructure:"allow-internal-registration"`
	Datastore                 *datastore.Config `yaml:"datastore" json:"datastore" mapstructure:"datastore"`
	DefaultTTL                int               `yaml:"default-ttl" json:"default_ttl" mapstructure:"default-ttl"`
	InternalServer            *InternalServer   `yaml:"internal" json:"internal" mapstructure:"internal"`
	Logger                    *logging.Logger   `yaml:"-" json:"-" mapstructure:"-"`
	PublicServer              *PublicServer     `yaml:"public" json:"public" mapstructure:"public"`
	PrivateIPv4               string            `yaml:"-" json:"-" mapstructure:"-"`
	PrivateIPv6               string            `yaml:"-" json:"-" mapstructure:"-"`
	PublicIPv4                string            `yaml:"-" json:"-" mapstructure:"-"`
	PublicIPv6                string            `yaml:"-" json:"-" mapstructure:"-"`
}

type PublicServer struct {
	Port       int           `yaml:"port" json:"port" mapstructure:"port"`
	Forwarders []string      `yaml:"forwarders" json:"forwarders" mapstructure:"forwarders"`
	Zone       entities.Zone `yaml:"zone" json:"zone" mapstructure:"zone"`
}

type InternalServer struct {
	Port       int           `yaml:"port" json:"port" mapstructure:"port"`
	Forwarders []string      `yaml:"forwarders" json:"forwarders" mapstructure:"forwarders"`
	Zone       entities.Zone `yaml:"zone" json:"zone" mapstructure:"zone"`
}
