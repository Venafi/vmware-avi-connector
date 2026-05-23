package domain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectionValidate(t *testing.T) {
	t.Parallel()

	t.Run("valid_hostname", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "avi-controller.example.com"}
		require.NoError(t, c.Validate())
	})

	t.Run("valid_hostname_single_label", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "avi-controller"}
		require.NoError(t, c.Validate())
	})

	t.Run("valid_ipv4_public", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "203.0.113.10"}
		require.NoError(t, c.Validate())
	})

	t.Run("valid_ipv4_private_rfc1918", func(t *testing.T) {
		// VMware AVI controllers are legitimately deployed on RFC 1918 private networks.
		c := &Connection{HostnameOrAddress: "10.0.0.1"}
		require.NoError(t, c.Validate())
	})

	t.Run("valid_ipv4_private_172_16", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "172.16.0.1"}
		require.NoError(t, c.Validate())
	})

	t.Run("valid_ipv4_private_192_168", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "192.168.1.100"}
		require.NoError(t, c.Validate())
	})

	t.Run("valid_ipv6_global_unicast", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "2001:db8::1"}
		require.NoError(t, c.Validate())
	})

	// --- rejection cases ---

	t.Run("reject_nil_connection", func(t *testing.T) {
		var c *Connection
		require.Error(t, c.Validate())
	})

	t.Run("reject_empty_hostnameOrAddress", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: ""}
		require.Error(t, c.Validate())
	})

	t.Run("reject_url_with_scheme", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "http://169.254.169.254/latest/meta-data/"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_url_with_path_only", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "169.254.169.254/latest/meta-data/"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_url_with_query", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "avi-controller.example.com?param=value"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_url_with_fragment", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "avi-controller.example.com#fragment"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_url_with_userinfo", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "user@avi-controller.example.com"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_ipv4_loopback", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "127.0.0.1"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_ipv4_loopback_other", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "127.100.200.1"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_ipv4_link_local_metadata", func(t *testing.T) {
		// Cloud instance-metadata endpoint used in SSRF attacks.
		c := &Connection{HostnameOrAddress: "169.254.169.254"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_ipv4_link_local_other", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "169.254.0.1"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_ipv4_unspecified", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "0.0.0.0"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_ipv4_multicast", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "224.0.0.1"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_ipv6_loopback", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "::1"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_ipv6_unspecified", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "::"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_ipv6_link_local", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "fe80::1"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_localhost_lowercase", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "localhost"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_localhost_mixed_case", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "LOCALHOST"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_invalid_hostname_leading_hyphen", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "-bad.example.com"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_invalid_hostname_trailing_hyphen", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "bad-.example.com"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_invalid_hostname_underscore", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "bad_host.example.com"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_invalid_hostname_space", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "bad host.example.com"}
		require.Error(t, c.Validate())
	})

	t.Run("reject_invalid_hostname_empty_label", func(t *testing.T) {
		c := &Connection{HostnameOrAddress: "bad..example.com"}
		require.Error(t, c.Validate())
	})
}
