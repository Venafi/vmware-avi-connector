package domain

import (
	"fmt"
	"net"
	"strings"
)

// Connection represents the properties defined in the connection definition in the manifest.json file.
type Connection struct {
	HostnameOrAddress string `json:"hostnameOrAddress"`
	Password          string `json:"password"`
	Port              int    `json:"port"`
	Username          string `json:"username"`
}

// Validate checks that the Connection fields are well-formed and safe from Server-Side Request
// Forgery (SSRF) attacks (CWE-918).  It must be called on every inbound request before the
// Connection is used to open a network connection.
func (c *Connection) Validate() error {
	if c == nil {
		return fmt.Errorf("connection must not be nil")
	}
	return validateHostnameOrAddress(c.HostnameOrAddress)
}

// validateHostnameOrAddress ensures that the supplied value is a safe, well-formed hostname or
// IP address that cannot be used to reach unintended internal destinations.
//
// Specifically it:
//   - rejects empty values
//   - tries to parse the value as an IP address first (supporting both IPv4 and IPv6 literals)
//     and, if successful, validates the address against unsafe ranges
//   - for non-IP values, rejects anything that contains URL structural characters
//     (scheme separator ":/", path "/", query "?", fragment "#", userinfo "@")
//   - rejects the hostname "localhost" (always resolves to the loopback interface)
//   - rejects values that are not otherwise a valid RFC 952 / RFC 1123 hostname
func validateHostnameOrAddress(hostnameOrAddress string) error {
	if len(hostnameOrAddress) == 0 {
		return fmt.Errorf("hostnameOrAddress must not be empty")
	}

	// Try to parse as an IP address literal first.  This must come before the URL-character
	// check because IPv6 addresses legitimately contain colons (e.g. "2001:db8::1").
	if ip := net.ParseIP(hostnameOrAddress); ip != nil {
		return validateIP(ip)
	}

	// Not an IP address.  Now reject anything that looks like a URL or contains characters
	// that have no place in a bare hostname.  This blocks inputs such as:
	//   http://169.254.169.254/latest/meta-data/
	//   169.254.169.254/latest/meta-data/
	//   user@host
	//   host?query=value
	if strings.ContainsAny(hostnameOrAddress, "/:?#@") {
		return fmt.Errorf(
			"hostnameOrAddress %q must be a plain hostname or IP address, not a URL",
			hostnameOrAddress,
		)
	}

	// Validate it as a hostname per RFC 952 / RFC 1123.
	if !isValidHostname(hostnameOrAddress) {
		return fmt.Errorf(
			"hostnameOrAddress %q is not a valid hostname or IP address",
			hostnameOrAddress,
		)
	}

	// Reject "localhost" by name: it always resolves to the loopback interface and is never a
	// legitimate VMware AVI controller address.
	if strings.EqualFold(hostnameOrAddress, "localhost") {
		return fmt.Errorf(
			"hostnameOrAddress %q resolves to a loopback address and must not be used",
			hostnameOrAddress,
		)
	}

	return nil
}

// validateIP returns an error when the provided IP address falls within a range that should
// never host a VMware AVI controller and could be exploited for SSRF.
func validateIP(ip net.IP) error {
	switch {
	case ip.IsLoopback():
		// Covers 127.0.0.0/8 and ::1.
		return fmt.Errorf("hostnameOrAddress %q must not be a loopback address", ip.String())
	case ip.IsLinkLocalUnicast():
		// Covers 169.254.0.0/16 (includes the AWS/GCP/Azure instance-metadata endpoint
		// 169.254.169.254) and fe80::/10.
		return fmt.Errorf("hostnameOrAddress %q must not be a link-local address", ip.String())
	case ip.IsLinkLocalMulticast():
		return fmt.Errorf("hostnameOrAddress %q must not be a link-local multicast address", ip.String())
	case ip.IsUnspecified():
		// Covers 0.0.0.0 and ::.
		return fmt.Errorf("hostnameOrAddress %q must not be an unspecified address", ip.String())
	case ip.IsMulticast():
		return fmt.Errorf("hostnameOrAddress %q must not be a multicast address", ip.String())
	}
	return nil
}

// isValidHostname returns true when hostname conforms to RFC 952 / RFC 1123 naming rules:
//   - total length 1–253 characters
//   - one or more dot-separated labels, each 1–63 characters
//   - each label contains only ASCII letters, digits, and hyphens
//   - no label starts or ends with a hyphen
func isValidHostname(hostname string) bool {
	const maxHostnameLen = 253
	const maxLabelLen = 63

	if len(hostname) == 0 || len(hostname) > maxHostnameLen {
		return false
	}

	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > maxLabelLen {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || ch == '-') {
				return false
			}
		}
	}

	return true
}
