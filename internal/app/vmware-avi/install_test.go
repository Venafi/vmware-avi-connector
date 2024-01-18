package vmware_avi

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	"github.com/venafi/vmware-avi-connector/internal/app/vmware-avi/mocks"
	"github.com/vmware/alb-sdk/go/models"
	"github.com/vmware/alb-sdk/go/session"
)

const (
	certificatePem = `-----BEGIN CERTIFICATE-----
MIIEzzCCA7egAwIBAgIUSKaW/pWPyKHRIdnhdJCXQifXXmgwDQYJKoZIhvcNAQEL
BQAweDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFZlbmFmaSwgSW5jLjERMA8GA1UE
CxMIQnVpbHQtaW4xPzA9BgNVBAMTNkRlZGljYXRlZCAtIFZlbmFmaSBDbG91ZCBC
dWlsdC1JbiBJbnRlcm1lZGlhdGUgQ0EgLSBHMTAeFw0yMzA4MjIyMzE0MjVaFw0y
MzExMjAyMzE0NTVaMCUxIzAhBgNVBAMTGmRlbGF5LmRheXRvbmEucWEudmVuYWZp
LmlvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt+xZmt1Vi85/qF4b
f/5HV6dgiF6tfY6FOlZrrJviUvIs2iMNnLE2gIYGvO65QXyHT/PRx67jKoUedve+
OTYFTyh4zsDt2s3Uac4tIBUGqb4iK87wRs+fJJSjNleU8cPEUgpEmIZo/7es+hwA
LEnGFOEddBXh5K/U/i3+Vv8iz48+C7o19Yplp4+1QAM6IsWjfgfONvc/jK+DfPV0
AWjv2/S9KQL27J14glQP/HK59UXoApFiWRuwMvliaFq9H8GgzHsbuat//v4Kg3uh
uOpIzPNpfDvQF/rUKgLufqABz5T9aY9ls/LsRrTSVqWmDD5cghojKrH9j1GdK2FD
/yIz7QIDAQABo4IBojCCAZ4wDgYDVR0PAQH/BAQDAgOoMB0GA1UdJQQWMBQGCCsG
AQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUK5oABv92t0BSdw+HfVg70ky78w4w
HwYDVR0jBBgwFoAUxJud+bFGy39w2JOHopAAgB+Hfl8wgYkGCCsGAQUFBwEBBH0w
ezB5BggrBgEFBQcwAoZtaHR0cDovL2J1aWx0aW5jYS1kZXYxMjcucWEudmVuYWZp
LmlvL3YxL2J1aWx0aW5jYS9jYWNoYWluLzJjYWJjNTIwLTQxMzktMTFlZS05MDU0
LTc1ZWM2YTdmODQ2Mi1JbnRlcm1lZGlhdGVDQTB6BgNVHR8EczBxMG+gbaBrhmlo
dHRwOi8vYnVpbHRpbmNhLWRldjEyNy5xYS52ZW5hZmkuaW8vdjEvYnVpbHRpbmNh
L2NybC8yY2FiYzUyMC00MTM5LTExZWUtOTA1NC03NWVjNmE3Zjg0NjItSW50ZXJt
ZWRpYXRlQ0EwJQYDVR0RBB4wHIIaZGVsYXkuZGF5dG9uYS5xYS52ZW5hZmkuaW8w
DQYJKoZIhvcNAQELBQADggEBAGZaU47tiG5Qjab5E4zrD0Ig6GXveS5oh//4HXfv
BVQcmyjMgGkbPk1ciqChzfxnZb8u1+sBe4vP0O+qj2fWwmXAjZ0lj2VJIeOpbgmI
+Nj3lx9HD7diky+NMvp+GQaWpsLT9MRRoUSukzPF9tm2g8mGuTq/m5yUhkGFmFsJ
tEdVSlsqS87sIQmM9e+zqwd0drYhDyfSOhoSOXfqPKYIr8b/CkvrRKBDcAW6ppZq
uWbd8IuZhmjFpIfNldydPhSuK7iX90CPdsigUqnLeYbPP9lFWeV8wxceVTdMAz5x
G0ZW7oajiA9wgidIb+eubDwrUkOAEoYTPI+TN8wJirHsCkA=
-----END CERTIFICATE-----`

	intermediateIssuerPem = `-----BEGIN CERTIFICATE-----
MIIExTCCA62gAwIBAgIUbzwBLPPE5351XVxGnPVD3dSwJsAwDQYJKoZIhvcNAQEL
BQAwZjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFZlbmFmaSwgSW5jLjERMA8GA1UE
CxMIQnVpbHQtaW4xLTArBgNVBAMTJERlZGljYXRlZCAtIFZlbmFmaSBDbG91ZCBC
dWlsdC1JbiBDQTAeFw0yMzA4MjIyMjEzMjNaFw0yODA4MjAyMjEzNTNaMHgxCzAJ
BgNVBAYTAlVTMRUwEwYDVQQKEwxWZW5hZmksIEluYy4xETAPBgNVBAsTCEJ1aWx0
LWluMT8wPQYDVQQDEzZEZWRpY2F0ZWQgLSBWZW5hZmkgQ2xvdWQgQnVpbHQtSW4g
SW50ZXJtZWRpYXRlIENBIC0gRzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDFnN716O+QqWwe1Gv9MnUhr2wUq8hLz0GfWqFx7vpMMSjFDdypH8k8AEP4
ys9QbYfshNBM15zKNdJ0ML9UDpfh43eAZCYjWWeScWRQPxYeCKtyxsXBe9zAzHbh
RyCtO11VJRuQBf6WwZRycCnwoBEIxJ+2MsWLRXCVuGOeXyAq3Ur88ij9n/iNm/4Q
GNMtyQVq/zee8FPfgGwmbsnXCE8RA21Oft/QF7azYD+X9PKNebZ/5M5dLlHLZChJ
7EEiU5zQHJB8jdFp7y/+sZntwGymlxWRfIfqCH1Rap8qa8xeLt2ebohSzbz/Gno6
9ZQpt+bYoQ5ItlannRt5FOgkXkSlAgMBAAGjggFXMIIBUzAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUxJud+bFGy39w2JOHopAAgB+H
fl8wHwYDVR0jBBgwFoAUovmmYW2m25do1TvT6pYJ3HX0oyowfAYIKwYBBQUHAQEE
cDBuMGwGCCsGAQUFBzAChmBodHRwOi8vYnVpbHRpbmNhLWRldjEyNy5xYS52ZW5h
ZmkuaW8vdjEvYnVpbHRpbmNhL2NhLzJjYWJjNTIwLTQxMzktMTFlZS05MDU0LTc1
ZWM2YTdmODQ2Mi1Sb290Q0EwcgYDVR0fBGswaTBnoGWgY4ZhaHR0cDovL2J1aWx0
aW5jYS1kZXYxMjcucWEudmVuYWZpLmlvL3YxL2J1aWx0aW5jYS9jcmwvMmNhYmM1
MjAtNDEzOS0xMWVlLTkwNTQtNzVlYzZhN2Y4NDYyLVJvb3RDQTANBgkqhkiG9w0B
AQsFAAOCAQEAgoBzc/coKLFzozJ7OGhJhhm2JMc4+Dk0JhXeR5cvRmt3PQIMrxee
KNeroDR2wYW+qzhssa8dcSlbN7GrdusoC5EpqziQXPpEt8g7cqrPaqWkERw+wynj
AcLxEakFdDJ210bpVTOxlNBW+IZwkEaA3K37jsyJnvjU+5DCFhrqNZQ+FqeFHzvB
QHUjzJDTC+6ACrHdHpg506NZAwq911bZJ8YlcOzfELC7hXo+ZoIvoFgg9K7mJsuz
syHAUmtrAwCRykcjNKLF20PXa2mvAA59ctYmgCcEYq7hzHGp5aLEHks8UyFtRGr1
fdGaDkXDs2L/B90FqJC1o10LW0u4eNmzFw==
-----END CERTIFICATE-----`

	rootIssuerPem = `-----BEGIN CERTIFICATE-----
MIIDvTCCAqWgAwIBAgIUfGrqwV3jHK3iDFFmYQgZ1+gR7VAwDQYJKoZIhvcNAQEL
BQAwZjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDFZlbmFmaSwgSW5jLjERMA8GA1UE
CxMIQnVpbHQtaW4xLTArBgNVBAMTJERlZGljYXRlZCAtIFZlbmFmaSBDbG91ZCBC
dWlsdC1JbiBDQTAeFw0yMzA4MjIyMjEzMjNaFw0zMzA4MTkyMjEzNTNaMGYxCzAJ
BgNVBAYTAlVTMRUwEwYDVQQKEwxWZW5hZmksIEluYy4xETAPBgNVBAsTCEJ1aWx0
LWluMS0wKwYDVQQDEyREZWRpY2F0ZWQgLSBWZW5hZmkgQ2xvdWQgQnVpbHQtSW4g
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfmBXdG25Z/1k+4ofM
/vCYpHNn0Nk/JCSVPE2fYlzJUup1Y/fVTm2+tqBYk6I29G38gbFVDHlm0mex4PmB
//JPhjsB1JwIuSTSDihzm8khaBPiIMyv/k7meS6g7H1Bdn+BI65gM61mY2H4lUXu
aKsd0/B2P9AQrwCityZv21ritBugT1j4YKUQJN1Mbkd76LBwzp23891l3oo4vzcB
4FVILJCRwY0+xXkJB3fh5HWDPFeHkjjatF4STSy8dML/Ijlohkm5yAdpcuTkTdBI
1AQFOIZaXUZhED13qYjcsD8i1fji86+CYL9esxp+9nKRlvHMvyCrv+spWcjIuYbq
W+i9AgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0G
A1UdDgQWBBSi+aZhbabbl2jVO9PqlgncdfSjKjAfBgNVHSMEGDAWgBSi+aZhbabb
l2jVO9PqlgncdfSjKjANBgkqhkiG9w0BAQsFAAOCAQEAOXR7ClYGKgg+oMG/5kb3
zOh0Ok2fOs+7VdQA8Aivp4SlxHs+m9tIB6Kij6wML+52hEt5Au60J4ED+Rd/j4hx
vJDl4+xku0nZ1gavEU9l8EhFlUgyPNY4os1dBn/V2/yZyUox+DKJrYre4IKRis3a
htAi2MSCXepG2vI50GFbdX2ww/lo/zQuGIRupMu3tkViv6lTEqOUL1xh9rM6NojN
eHKeeYUdRDe8/5rQlpaP0jSe4L9Nl2DPNRsy4vW6Kt80wWVUiM1+ps5Gg31260u9
Wth70wKz7+KYJ4uiD1NU3370PZQD2ZuLNNH15QcD3SNixR41ZaCwfOPJ5ZcU8IYM
sw==
-----END CERTIFICATE-----`

	privateKeyPem = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC37Fma3VWLzn+o
Xht//kdXp2CIXq19joU6Vmusm+JS8izaIw2csTaAhga87rlBfIdP89HHruMqhR52
9745NgVPKHjOwO3azdRpzi0gFQapviIrzvBGz58klKM2V5Txw8RSCkSYhmj/t6z6
HAAsScYU4R10FeHkr9T+Lf5W/yLPjz4LujX1imWnj7VAAzoixaN+B8429z+Mr4N8
9XQBaO/b9L0pAvbsnXiCVA/8crn1RegCkWJZG7Ay+WJoWr0fwaDMexu5q3/+/gqD
e6G46kjM82l8O9AX+tQqAu5+oAHPlP1pj2Wz8uxGtNJWpaYMPlyCGiMqsf2PUZ0r
YUP/IjPtAgMBAAECggEAENMLA1KZ37cdEF7Dbzrodck22GKoxiKCZ2q+YMTFuEa0
+aNZPGstjCY2eZPw2F+21QZ9uyFxYFNbDRDukrcxVyNhobAeUfSgKKmWkSe7O03M
PGuqqR+W9Dawk2kBk/gPfl24Fqe89R9tMFfdYC/DceeB1TunNU8sUbANYxHlskzF
alBXlB+z5Gcy1+kLSPtEXRVwIQj/WfsqeZz4vF07S+nkU21ba8hZtij35L2YpD1A
0veyzdf301n5O7EBZcuN6xO5by+IdlbgFSP2sK0vIXB8tSwru88L+RBTDfgKOAQH
mb4sN7A5lKlxoouUi8XFfRSPqxd9y497IAaMgbXoAQKBgQDQi8Qsd3yUKrfC1fAr
km2YzmLhX0pMy3/8j6DxaJ7GoS2LMiamsTotKe/rEHEr7B4hY0ZlS1H7pAcUwkoc
XTtxH8lJwOef5SNbQ/GzQ5g6PIIUgxe9rQhpqOjlW9xJmLmvpvTNaxbNS6NCEz3S
M2RHGgFKVfVN/DqHzGdUr1CqAQKBgQDhxkJkrzwmSjHeCm0bi1L89rWR6MBGn23E
eG9a3pEKOLho84ArHiWGmB3aoeWRi1vpoO+djGjp1k9/U2IZnaGn8JtAZ1KZ8lcZ
1RSB7K2/MmLOj6D648LP9ctUlAHCCI6Knt8tJo0RUiMv15K9SQRj8UErLP7r/vyq
CeJ38qrR7QKBgG06p3d65f9dGH6uO2s2+LxubRAKLwpmFBUezXdkCrWSuh4MGH56
mTQKoSUHqZ8NvwJR0w8/EiOxWBwhX1vX4UhxE6bTqP3wsEIfJjt0jgkCpEdGGms4
dA2TcNig8pKBsdA0rEfjbT/9+/ahyWGNlVpAXqimuSMtlyKFhyGt6ZwBAoGAL9LJ
GX6s5QduTLQ0rFL0vzSa/U8p+0ul+qnwHHVsj5e4KDL8ASYfmMT7/eWxNQUp8PDw
EJU/W9jTegr1iquDJImouRmpu4ZDwOsLrwGtRASuPUbbOImqKFbOPRokzS720pIY
f/3cf8DAR1AIeyPOVEU0IqsjTGX0qyfw2quCV3kCgYEAuYUgJwdyU1tKmjuqmW/X
8k95sQouIXsv0bKNhlJvHTGa7buY+EO3n7uIwcZ7FaCkJsqeGzqz92a0kefL2qg3
LcP/UAVB74E2OdATWLgiqvNHH618glEcvB2pllhGGyg/NZqzha8AgCNiE9DGYsAO
MgpIYf510QSbWvjEvPmh5IQ=
-----END PRIVATE KEY-----`
)

var (
	certificateDer      []byte
	certificateChainDer [][]byte
	privateKeyDer       []byte
)

func pemParse(content []byte) [][]byte {
	collection := make([][]byte, 0)

	var block *pem.Block

	remaining := content
	for {
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}

		switch block.Type {
		case "CERTIFICATE":
			// parse the tls certificate
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				collection = append(collection, cert.Raw)
			}
		case "PRIVATE KEY":
			collection = append(collection, block.Bytes)
		}
	}

	return collection
}

func init() {
	collection := pemParse([]byte(certificatePem))
	if collection != nil && len(collection) > 0 {
		certificateDer = collection[0]
	}

	var intermediate []byte
	collection = pemParse([]byte(intermediateIssuerPem))
	if collection != nil && len(collection) > 0 {
		intermediate = collection[0]
	}

	var root []byte
	collection = pemParse([]byte(rootIssuerPem))
	if collection != nil && len(collection) > 0 {
		root = collection[0]
	}

	if intermediate != nil && root != nil {
		certificateChainDer = [][]byte{
			intermediate,
			root,
		}
	}

	collection = pemParse([]byte(privateKeyPem))
	if collection != nil && len(collection) > 0 {
		privateKeyDer = collection[0]
	}
}

func TestInstall(t *testing.T) {
	var err error

	e := echo.New()

	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClientServices := mocks.NewMockClientServices(ctrl)

		whService := NewWebhookService(mockClientServices, nil)
		require.NotNil(t, whService)

		var raw []byte

		raw, err = json.Marshal(&InstallCertificateBundleRequest{
			Connection: &domain.Connection{
				HostnameOrAddress: "localhost",
				Password:          "password",
				Port:              443,
				Username:          "user",
			},
			CertificateBundle: domain.CertificateBundle{
				Certificate:      certificateDer,
				PrivateKey:       privateKeyDer,
				CertificateChain: certificateChainDer,
			},
			InstallationKeystore: domain.Keystore{
				CertificateName: "installation.test.io",
				Tenant:          "test",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, raw)

		recorder, ctx := setupPost(e, "/v1/installcertificatebundle", bytes.NewReader(raw))
		require.NotNil(t, ctx)
		require.NotNil(t, recorder)

		mockClientServices.EXPECT().
			NewClient(gomock.Any(), gomock.Any()).
			DoAndReturn(func(connection *domain.Connection, tenant string) *domain.Client {
				return &domain.Client{
					Connection: connection,
					Tenant:     tenant,
				}
			})
		mockClientServices.EXPECT().
			Connect(gomock.Any()).
			Return(nil)
		mockClientServices.EXPECT().
			Close(gomock.Any())

		mockClientServices.EXPECT().
			GetSSLKeyAndCertificateByName(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(client *domain.Client, name string, options ...session.ApiOptionsParams) (*models.SSLKeyAndCertificate, error) {
				return nil, errors.New(fmt.Sprintf("No object of type sslkeyandcertificate with name %s is found", name))
			}).
			Times(3)
		mockClientServices.EXPECT().
			CreateSSLKeyAndCertificate(gomock.Any(), gomock.Any()).
			DoAndReturn(func(client *domain.Client, obj *models.SSLKeyAndCertificate, options ...session.ApiOptionsParams) (*models.SSLKeyAndCertificate, error) {
				return obj, nil
			}).
			Times(3)

		err = whService.HandleInstallCertificateBundle(ctx)
		require.NoError(t, err)

		response := recorder.Result()
		defer func() {
			_ = response.Body.Close()
		}()
		require.NotNil(t, response)
		require.Equal(t, response.StatusCode, http.StatusOK)

		body := recorder.Body.String()
		require.NotNil(t, body)
	})
}
