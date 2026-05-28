package vmwareavi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCertificateDer(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		certificate, err := parseCertificatePEM([]byte(certificatePem))
		require.NoError(t, err)
		require.NotNil(t, certificate)

		require.Equal(t, "delay.daytona.qa.venafi.io", certificate.Subject.CommonName)
		require.Equal(t, "Dedicated - Venafi Cloud Built-In Intermediate CA - G1", certificate.Issuer.CommonName)

		certificate, err = parseCertificateDER(certificate.Raw)
		require.NoError(t, err)
		require.NotNil(t, certificate)

		require.Equal(t, "delay.daytona.qa.venafi.io", certificate.Subject.CommonName)
		require.Equal(t, "Dedicated - Venafi Cloud Built-In Intermediate CA - G1", certificate.Issuer.CommonName)
	})
}

func TestGetCertificateName(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		certificate, err := parseCertificateDER(certificateDer)
		require.NoError(t, err)
		require.NotNil(t, certificate)

		var name string

		name, err = getCertificateName(certificate, "")
		require.NoError(t, err)
		require.Equal(t, "delay.daytona.qa.venafi.io-231120-6568", name)

		name, err = getCertificateName(certificate, "test")
		require.NoError(t, err)
		require.Equal(t, "test-231120-6568", name)
	})
}

// TestValidateHostnameOrAddress covers the SSRF-prevention validation introduced to
// remediate CWE-918.  It verifies that legitimate VMware AVI hostnames and IP addresses
// are accepted and that all classes of dangerous or malformed input are rejected.
func TestValidateHostnameOrAddress(t *testing.T) {
	t.Parallel()

	validCases := []struct {
		name  string
		input string
	}{
		// Plain hostnames
		{"simple hostname", "avi-controller.example.com"},
		{"single-label hostname", "avicontroller"},
		{"hostname with hyphens", "my-avi-host.corp.example.com"},
		{"numeric hostname label", "host1.example.com"},
		{"hostname with mixed case", "AviController.Example.COM"},
		// Private IPv4 addresses (legitimate AVI controller deployments)
		{"private IPv4 RFC1918 class A", "10.0.0.1"},
		{"private IPv4 RFC1918 class B", "172.16.0.1"},
		{"private IPv4 RFC1918 class C", "192.168.1.100"},
		// Public IPv4 address
		{"public IPv4", "203.0.113.10"},
		// Non-reserved IPv6
		{"global unicast IPv6", "2001:db8::1"},
		{"full IPv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
	}

	for _, tc := range validCases {
		tc := tc
		t.Run("valid/"+tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateHostnameOrAddress(tc.input)
			require.NoError(t, err, "expected %q to be accepted", tc.input)
		})
	}

	invalidCases := []struct {
		name        string
		input       string
		errContains string
	}{
		// Empty / whitespace
		{"empty string", "", "must not be empty"},
		{"whitespace only", "   ", "must not be empty"},

		// URL scheme injection
		{"https scheme", "https://avi-controller.example.com", "URL scheme"},
		{"http scheme", "http://192.168.1.1", "URL scheme"},
		{"ftp scheme", "ftp://files.example.com", "URL scheme"},
		{"custom scheme", "avi://controller.example.com", "URL scheme"},

		// URL path / query / fragment / userinfo injection
		{"path component", "avi-controller.example.com/api/login", "URL-specific characters"},
		{"query string", "avi-controller.example.com?tenant=admin", "URL-specific characters"},
		{"fragment", "avi-controller.example.com#section", "URL-specific characters"},
		{"userinfo delimiter", "admin@avi-controller.example.com", "URL-specific characters"},
		{"IPv6 brackets without port", "[::1]", "URL-specific characters"},
		{"IPv6 brackets with port", "[2001:db8::1]:443", "URL-specific characters"},

		// Loopback addresses
		{"IPv4 loopback", "127.0.0.1", "loopback"},
		{"IPv4 loopback non-zero host", "127.0.0.2", "loopback"},
		{"IPv6 loopback", "::1", "loopback"},

		// Link-local addresses (includes cloud metadata services)
		{"IPv4 link-local – AWS IMDS", "169.254.169.254", "link-local"},
		{"IPv4 link-local – GCP IMDS", "169.254.169.253", "link-local"},
		{"IPv4 link-local – first in range", "169.254.0.1", "link-local"},
		{"IPv6 link-local unicast", "fe80::1", "link-local"},
		{"IPv6 link-local multicast", "ff02::1", "link-local"},

		// Unspecified addresses
		{"IPv4 unspecified", "0.0.0.0", "unspecified"},
		{"IPv6 unspecified", "::", "unspecified"},

		// localhost alias
		{"localhost lowercase", "localhost", "must not be localhost"},
		{"localhost uppercase", "LOCALHOST", "must not be localhost"},
		{"localhost mixed case", "LocalHost", "must not be localhost"},

		// Port smuggling (port is a separate request field)
		{"hostname with port", "avi-controller.example.com:443", "colon"},
		{"IP with port", "192.168.1.1:443", "colon"},

		// Invalid hostname format
		{"empty label (double dot)", "avi..example.com", "empty labels"},
		{"label starts with hyphen", "-avi.example.com", "invalid label"},
		{"label ends with hyphen", "avi-.example.com", "invalid label"},
		{"label with underscore", "avi_controller.example.com", "invalid label"},
		{"label with space", "avi controller.example.com", "invalid label"},
		{"label with special char", "avi*controller.example.com", "invalid label"},
	}

	for _, tc := range invalidCases {
		tc := tc
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateHostnameOrAddress(tc.input)
			require.Error(t, err, "expected %q to be rejected", tc.input)
			require.ErrorContains(t, err, tc.errContains,
				"expected error message to contain %q for input %q", tc.errContains, tc.input)
		})
	}
}
