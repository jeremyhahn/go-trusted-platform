package dns

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

var (
	macros = map[string]string{
		"PUBLIC_IPv4":   "",
		"PUBLIC_IPv6":   "",
		"PRIVATE_IPv4":  "",
		"PRIVATE_IPv6":  "",
		"HOSTNAME":      "",
		"PUBLIC_DOMAIN": "",
		"PRVATE_DOMAIN": "",
		"PUBLIC_FQDN":   "",
		"PRIVATE_FQDN":  "",
	}

	ErrMacroNotFound = errors.New("dns: macro not found")
)

func setupMacros() {

	macros["PRIVATE_IPv4"] = Configuration.PrivateIPv4
	macros["PRIVATE_IPv6"] = Configuration.PrivateIPv6
	macros["PUBLIC_IPv4"] = Configuration.PublicIPv4
	macros["PUBLIC_IPv6"] = Configuration.PublicIPv6
	macros["PREFERRED_IP"] = util.PreferredIPv4().String()

	hostname, err := os.Hostname()
	if err != nil {
		panic("Unable to get the local hostname")
	}
	macros["HOSTNAME"] = hostname

	if Configuration.PublicServer != nil {
		macros["PUBLIC_DOMAIN"] = Configuration.PublicServer.Zone.Name
		macros["PUBLIC_FQDN"] = fmt.Sprintf("%s.%s",
			hostname, Configuration.PublicServer.Zone.Name)
	}
	if Configuration.InternalServer != nil {
		macros["PRIVATE_DOMAIN"] = Configuration.InternalServer.Zone.Name
		macros["PRIVATE_FQDN"] = fmt.Sprintf("%s.%s",
			hostname, Configuration.InternalServer.Zone.Name)
	}
}

func ExpandVar(env string) string {
	re := regexp.MustCompile(`\$\{([^}]+)\}`)

	matches := re.FindStringSubmatch(env)
	if len(matches) == 0 {
		return env
	}

	if len(matches) != 2 {
		panic("multiple dns macros not suppoted in record values")
	}

	return macros[matches[1]]
}

func Expand(zone *entities.Zone) error {

	for _, record := range zone.RecordSet.ARecords {
		// record.Value = os.ExpandVar(record.Value) - support os env vars?
		record.Name = ExpandVar(record.Name)
		record.Value = ExpandVar(record.Value)
	}

	for _, record := range zone.RecordSet.AAAARecords {
		record.Name = ExpandVar(record.Name)
		record.Value = ExpandVar(record.Value)
	}

	for _, record := range zone.RecordSet.CNAMERecords {
		record.Name = ExpandVar(record.Name)
		record.Value = ExpandVar(record.Value)
	}

	for _, record := range zone.RecordSet.MXRecords {
		record.Name = ExpandVar(record.Name)
		record.Value = ExpandVar(record.Value)
	}

	for _, record := range zone.RecordSet.NSRecords {
		record.Name = ExpandVar(record.Name)
		record.Value = ExpandVar(record.Value)
	}

	for _, record := range zone.RecordSet.SRVRecords {
		record.Name = ExpandVar(record.Name)
		record.Target = ExpandVar(record.Target)
	}

	for _, record := range zone.RecordSet.TXTRecords {
		record.Name = ExpandVar(record.Name)
		record.Value = ExpandVar(record.Value)
	}

	return nil
}
