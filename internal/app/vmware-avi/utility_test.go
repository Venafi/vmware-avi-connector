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
