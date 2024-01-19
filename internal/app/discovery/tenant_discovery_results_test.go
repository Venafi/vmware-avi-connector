package discovery

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTenantDiscoveryResults(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tdr := newTenantDiscoveryResults()
		require.NotNil(t, tdr)

		tdr.append("third", []*discoveredCertificateAndURL{
			&discoveredCertificateAndURL{
				Name: "31",
				Result: &DiscoveredCertificate{
					Certificate: "c-31",
				},
				UUID: "81671742-4965-4cd0-a516-77c9b1f6c6e2",
			},
		})

		tdr.append("second", []*discoveredCertificateAndURL{
			&discoveredCertificateAndURL{
				Name: "20",
				Result: &DiscoveredCertificate{
					Certificate: "c-2-a",
				},
				UUID: "86d0b1b5-4e6c-40f3-9a2f-cf2e271d61fe",
			},
			&discoveredCertificateAndURL{
				Name: "21",
				Result: &DiscoveredCertificate{
					Certificate: "c-2-b",
				},
				UUID: "e0b796a3-f9d2-4c67-a7dd-172f6bd22c23",
			},
		})

		tdr.append("first", []*discoveredCertificateAndURL{
			&discoveredCertificateAndURL{
				Name: "1",
				Result: &DiscoveredCertificate{
					Certificate: "c-1",
				},
				UUID: "48ff48c9-2818-4907-a025-4cb802b1fc53",
			},
		})

		tdr.append("third", []*discoveredCertificateAndURL{
			&discoveredCertificateAndURL{
				Name: "32",
				Result: &DiscoveredCertificate{
					Certificate: "c-32",
				},
				UUID: "1aa30f64-d2da-4f7a-b820-4dfaba37e491",
			},
		})

		require.Equal(t, 5, tdr.Discovered)

		require.Contains(t, tdr.TenantMap, "first")
		require.NotNil(t, tdr.TenantMap["first"])
		require.Equal(t, 1, len(tdr.TenantMap["first"]))
		require.Contains(t, tdr.TenantMap, "second")
		require.NotNil(t, tdr.TenantMap["second"])
		require.Equal(t, 2, len(tdr.TenantMap["second"]))
		require.Contains(t, tdr.TenantMap, "third")
		require.NotNil(t, tdr.TenantMap["third"])
		require.Equal(t, 2, len(tdr.TenantMap["third"]))

		collapsed := tdr.collapse()
		require.NotNil(t, collapsed)
		require.Equal(t, 5, len(collapsed))
	})
}
