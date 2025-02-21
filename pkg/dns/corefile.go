package dns

import (
	"fmt"
	"strings"
)

func NewCorefile(port int) string {
	return fmt.Sprintf(`
.:%d {
	trustedPlatform
	log
	chaos
}
`, port)
}

func NewCorefileWithForwarders(port int, forwarders []string) string {
	return fmt.Sprintf(`
.:%d {
	trustedPlatform
	log
	chaos
	forward . %s
}
`, port, strings.Join(forwarders, " "))
}
