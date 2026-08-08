// Package platform provides cross-platform system information helpers used by
// the agent during registration.
package platform

import (
	"net"
	"os"
	"strings"
)

// GetInternalIP returns the first non-loopback IPv4 address, or "0.0.0.0".
func GetInternalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "0.0.0.0"
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	return "0.0.0.0"
}

// GetProcessPath returns the absolute path of the current executable.
func GetProcessPath() string {
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return exe
}

// getDomainFromEnv extracts the Windows domain or workgroup from environment
// variables. It is a shared helper for the platform-specific GetDomain.
func getDomainFromEnv() string {
	if d := os.Getenv("USERDNSDOMAIN"); d != "" {
		return d
	}
	if d := os.Getenv("USERDOMAIN"); d != "" {
		return d
	}
	if d := os.Getenv("LOGONSERVER"); d != "" {
		return strings.TrimPrefix(d, `\\`)
	}
	return ""
}
