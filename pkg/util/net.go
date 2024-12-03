package util

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
)

// Performs a logical UDP connection to an endpoint
// that does not need to exist and returns the local
// IP address that was used to perform the connection.
func PreferredIPv4() net.IP {
	conn, err := net.Dial("udp", "1.2.3.4:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// Performs a logical UDP connection to an endpoint
// that does not need to exist and returns the local
// IP address that was used to perform the connection.
func PreferredIPv6() net.IP {
	conn, err := net.Dial("udp", "[::1]:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// Parses a list of usable local IP addresses
func LocalAddresses() ([]string, error) {
	ips := make([]string, 0)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			ips = append(ips, ipNet.IP.String())
		}
	}
	return ips, nil
}

// Returns true if the provided IP falls within a private address range
func IsPrivateSubnet(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// Returns the Fully Qualified Domain Name for a given URL
func ParseFQDN(anyURL string) (string, error) {
	parsedURL, err := url.Parse(anyURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	host := parsedURL.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0] // Remove port if present
	}
	return host, nil
}
