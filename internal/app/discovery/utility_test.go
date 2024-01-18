package discovery

import (
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vmware/alb-sdk/go/models"
)

func TestUtility(t *testing.T) {
	t.Parallel()

	t.Run("contains", func(t *testing.T) {
		tenants := TenantNames{
			"alpha",
			"beta",
			"charlie",
		}

		require.True(t, tenants.contains("beta"))
		require.False(t, tenants.contains("delta"))
	})

	t.Run("getCertificateName", func(t *testing.T) {
		certificate := &models.SSLKeyAndCertificate{}

		id := "sslkeyandcertificate:" + uuid.New().String()
		value := "https://localhost/api/sslkeyandcertificate/" + id
		certificate.URL = &value

		require.Equal(t, id, getCertificateName(certificate))

		value = uuid.New().String()
		certificate.UUID = &value

		require.Equal(t, value, getCertificateName(certificate))

		value = "test"
		certificate.Name = &value

		require.Equal(t, value, getCertificateName(certificate))
	})

	t.Run("getValue", func(t *testing.T) {
		value := "value"

		require.Equal(t, value, getValue(&value))

		require.Equal(t, "nil", getValue(nil))

		value = ""
		require.Equal(t, "empty", getValue(&value))
	})

	t.Run("getVirtualServiceName", func(t *testing.T) {
		vs := &models.VirtualService{}

		id := "virtualservice:" + uuid.New().String()
		value := "https://localhost/api/virtualservice/" + id
		vs.URL = &value

		require.Equal(t, id, getVirtualServiceName(vs))

		value = uuid.New().String()
		vs.UUID = &value

		require.Equal(t, value, getVirtualServiceName(vs))

		value = "vs1"
		vs.Name = &value

		require.Equal(t, value, getVirtualServiceName(vs))
	})

	t.Run("isExpired", func(t *testing.T) {
		certificate := &models.SSLCertificate{}

		notAfter := time.Now().Add(time.Hour * -24).Format(CertificateValidityDateFormat)
		certificate.NotAfter = &notAfter

		expired, err := isExpired(certificate)
		require.NoError(t, err)
		require.True(t, expired)

		notAfter = time.Now().Add(time.Hour * 24).Format(CertificateValidityDateFormat)
		certificate.NotAfter = &notAfter

		expired, err = isExpired(certificate)
		require.NoError(t, err)
		require.False(t, expired)
	})

	t.Run("lessLower", func(t *testing.T) {
		tenants := TenantNames{
			"charlie",
			"alpha",
			"betas",
			"beta",
			"echo",
		}

		sort.Slice(tenants, func(i, j int) bool {
			return lessLower(tenants[i], tenants[j])
		})

		for idx := 0; idx < len(tenants); idx++ {
			switch idx {
			case 0:
				require.Equal(t, "alpha", tenants[idx])
			case 1:
				require.Equal(t, "beta", tenants[idx])
			case 2:
				require.Equal(t, "betas", tenants[idx])
			case 3:
				require.Equal(t, "charlie", tenants[idx])
			case 4:
				require.Equal(t, "echo", tenants[idx])
			default:

			}
		}
	})

	t.Run("reverse", func(t *testing.T) {
		indices := []int{
			1, 2, 3, 4, 5, 6, 7, 8, 9,
		}

		reverse(indices)

		for idx := 0; idx < 9; idx++ {
			require.Equal(t, 9-idx, indices[idx])
		}
	})
}
