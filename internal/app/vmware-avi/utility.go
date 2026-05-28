package vmwareavi

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// hostnameComponentRegex validates a single dot-separated label of a hostname per RFC 1123.
// A valid label starts and ends with an alphanumeric character and may contain hyphens
// in the middle.  Single-character labels (e.g. the "a" in "a.b.c") are also accepted.
var hostnameComponentRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)

// ValidateHostnameOrAddress validates the hostnameOrAddress parameter to mitigate
// Server-Side Request Forgery (SSRF) attacks (CWE-918).
//
// The value must be a plain hostname or bare IP address – no URL schemes, path
// components, query strings, fragment identifiers, userinfo delimiters, or IPv6
// bracket notation are accepted.
//
// Additionally, the following address types are rejected because they refer to the
// local host or to cloud-provider metadata endpoints that must never be reachable
// through a user-supplied connection parameter:
//   - Loopback addresses   (127.0.0.0/8, ::1)
//   - Link-local addresses (169.254.0.0/16, fe80::/10) – includes AWS/GCP/Azure IMDS
//   - Unspecified addresses (0.0.0.0, ::)
//   - The "localhost" hostname alias
func ValidateHostnameOrAddress(hostnameOrAddress string) error {
	if len(strings.TrimSpace(hostnameOrAddress)) == 0 {
		return errors.New("hostnameOrAddress must not be empty")
	}

	// Reject any value that embeds a URL scheme (e.g. "http://", "https://", "ftp://").
	if strings.Contains(hostnameOrAddress, "://") {
		return errors.New("hostnameOrAddress must not contain a URL scheme")
	}

	// Reject characters that are only meaningful inside a URL, not in a standalone
	// hostname or IP address:
	//   /  – path separator
	//   ?  – query string delimiter
	//   #  – fragment delimiter
	//   @  – userinfo / host separator (e.g. "user@host")
	//   [  – IPv6 bracket notation start (valid in URLs, not as a bare host value)
	//   ]  – IPv6 bracket notation end
	if strings.ContainsAny(hostnameOrAddress, `/?#@[]`) {
		return errors.New("hostnameOrAddress must not contain URL-specific characters (/, ?, #, @, [ or ])")
	}

	// Try to interpret the value as a bare IP address (IPv4 or IPv6).
	if ip := net.ParseIP(hostnameOrAddress); ip != nil {
		return validateIP(ip)
	}

	// A colon that survives the IP-address check is a sign of a malformed value –
	// either an attempt to smuggle a port number (the port is a separate request
	// field) or an invalid IPv6 literal.
	if strings.ContainsRune(hostnameOrAddress, ':') {
		return errors.New("hostnameOrAddress must not contain a colon unless it is a valid IPv6 address")
	}

	// Block the well-known "localhost" alias because it always resolves to a loopback
	// address regardless of any DNS overrides.
	if strings.EqualFold(hostnameOrAddress, "localhost") {
		return errors.New("hostnameOrAddress must not be localhost")
	}

	return validateHostname(hostnameOrAddress)
}

// validateIP rejects IP addresses that refer to dangerous or reserved targets.
func validateIP(ip net.IP) error {
	if ip.IsLoopback() {
		return errors.New("hostnameOrAddress must not be a loopback address")
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return errors.New("hostnameOrAddress must not be a link-local address")
	}
	if ip.IsUnspecified() {
		return errors.New("hostnameOrAddress must not be an unspecified address")
	}
	return nil
}

// validateHostname checks that the value is a syntactically valid hostname per RFC 1123.
// Each dot-separated label must be 1–63 characters long, must start and end with an
// alphanumeric character, and may only contain alphanumeric characters and hyphens.
// The overall hostname must not exceed 253 characters.
func validateHostname(hostname string) error {
	if len(hostname) > 253 {
		return errors.New("hostnameOrAddress must not exceed 253 characters")
	}

	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return errors.New("hostnameOrAddress must not contain empty labels")
		}
		if len(label) > 63 {
			return errors.New("hostnameOrAddress label must not exceed 63 characters")
		}
		if !hostnameComponentRegex.MatchString(label) {
			return fmt.Errorf("hostnameOrAddress contains an invalid label: %q", label)
		}
	}

	return nil
}

func getCertificateName(certificate *x509.Certificate, baseName string) (string, error) {
	var err error
	suffix := ""
	if certificate.SerialNumber.BitLen() > 0 {
		sn := certificate.SerialNumber.String()
		if len(sn) > 4 {
			sn = sn[len(sn)-4:]
		}
		suffix = sn
	}

	if baseName == "" {
		baseName = fmt.Sprintf("%q", certificate.Subject.CommonName)
		baseName, err = normalizeDiacritics(baseName[1 : len(baseName)-1])
		if err != nil {
			return "", fmt.Errorf("unable to read common name: %w", err)
		}
	}

	return fmt.Sprintf("%s-%s-%s", baseName, certificate.NotAfter.Format("060102"), suffix), nil
}

func normalizeDiacritics(input string) (string, error) {
	normalized, _, err := transform.String(norm.NFD, input)
	if err == nil {
		return normalized, nil
	}
	return "", err
}

func parseCertificateDER(content []byte) (*x509.Certificate, error) {
	var err error
	var certificate *x509.Certificate

	certificate, err = x509.ParseCertificate(content)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %w", err)
	}

	return certificate, nil
}

func parseCertificatePEM(content []byte) (*x509.Certificate, error) {
	var block *pem.Block

	remaining := make([]byte, len(content))
	copy(remaining, content)

	for {
		block, _ = pem.Decode(remaining)
		if block == nil {
			break
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing TLS certificate: %s", err)
		}

		return cert, nil
	}

	return nil, nil
}
