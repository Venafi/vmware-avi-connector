package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	"github.com/venafi/vmware-avi-connector/internal/app/vmware-avi/mocks"
	"github.com/vmware/alb-sdk/go/models"
	"github.com/vmware/alb-sdk/go/session"
	"go.uber.org/mock/gomock"
)

const (
	CertificateValidityDateFormat = "2006-01-02 15:04:05"
)

func findDiscoveredCertificate(available []*DiscoveredCertificate, actual *DiscoveredCertificate) *DiscoveredCertificate {
	for _, dc := range available {
		if strings.EqualFold(dc.Certificate, actual.Certificate) {
			return dc
		}
	}

	return nil
}

func getParameterOptionsValue(key string, options ...session.ApiOptionsParams) (string, error) {
	var err error

	opts := &session.ApiOptions{}
	for _, opt := range options {
		err = opt(opts)
		if err != nil {
			return "", err
		}
	}

	fv := reflect.ValueOf(opts).Elem().FieldByName("params")
	if fv.IsNil() {
		return "", errors.New("the expected field name params was not found")
	}

	if !fv.CanConvert(reflect.TypeOf(map[string]string{})) {
		return "", errors.New("the params field has an unsupported value type")
	}

	fv = fv.Convert(reflect.TypeOf(map[string]string{}))

	iter := fv.MapRange()
	for iter.Next() {
		kv := iter.Key()
		ks := kv.String()
		if ks != key {
			continue
		}

		return iter.Value().String(), nil
	}

	return "", nil
}

func setupDiscovery(
	t *testing.T,
	clientServices *mocks.MockClientServices,
	maxResults int,
	sslKeysAndCertificates map[string][]*models.SSLKeyAndCertificate,
	tenantVirtualServices map[string]map[string][]*models.VirtualService) (tdr *tenantDiscoveryResults, err error) {

	var ok bool

	times := setupExpectGetAllSSLKeysAndCertificates(clientServices, sslKeysAndCertificates, maxResults)

	setupExpectClientUsage(clientServices, times)

	times = 0
	for _, collection := range sslKeysAndCertificates {
		times += len(collection)
	}

	clientServices.EXPECT().
		GetAllVirtualServices(gomock.Any(), gomock.Any()).
		DoAndReturn(func(client *domain.Client, options ...session.ApiOptionsParams) ([]*models.VirtualService, error) {
			var referencedVirtualServices map[string][]*models.VirtualService

			referencedVirtualServices, ok = tenantVirtualServices[client.Tenant]
			require.True(t, ok)

			var refersTo string

			refersTo, err = getParameterOptionsValue("refers_to", options...)
			require.NoError(t, err)
			require.NotEmpty(t, refersTo)

			var virtualServices []*models.VirtualService
			virtualServices, ok = referencedVirtualServices[refersTo]
			require.True(t, ok)

			return virtualServices, nil
		}).
		Times(times)

	tdr = newTenantDiscoveryResults()
	for tenant, certificates := range sslKeysAndCertificates {
		discovered := make([]*discoveredCertificateAndURL, 0)
		for _, certificate := range certificates {
			dcu := &discoveredCertificateAndURL{
				Name: getCertificateName(certificate),
				Result: &DiscoveredCertificate{
					Certificate:       *certificate.Certificate.Certificate,
					CertificateChain:  make([]string, 0),
					Installations:     make([]*CertificateInstallation, 0),
					MachineIdentities: make([]*MachineIdentity, 0),
				},
				UUID: *certificate.UUID,
			}

			var referencedVirtualServices map[string][]*models.VirtualService
			referencedVirtualServices, ok = tenantVirtualServices[tenant]
			require.True(t, ok)

			var certificateUUID string
			certificateUUID, err = getUUIDFromURL(*certificate.URL)
			require.NoError(t, err)

			var virtualServices []*models.VirtualService
			virtualServices, ok = referencedVirtualServices[certificateUUID]
			for _, vs := range virtualServices {
				mi := &MachineIdentity{
					Keystore: &domain.Keystore{
						CertificateName: getCertificateName(certificate),
						Tenant:          tenant,
					},
					Binding: &domain.Binding{
						VirtualServiceName: getVirtualServiceName(vs),
					},
				}

				dcu.Result.MachineIdentities = append(dcu.Result.MachineIdentities, mi)
			}

			discovered = append(discovered, dcu)
		}
		tdr.append(tenant, discovered)
	}

	return tdr, nil
}

func setupExpectGetAllSSLKeysAndCertificates(clientServices *mocks.MockClientServices, responses map[string][]*models.SSLKeyAndCertificate, maxResults int) int {
	limit := maxResults
	times := 0
	for _, collection := range responses {
		count := len(collection)
		for count > limit {
			times++

			count -= limit

			limit = maxResults
		}

		limit -= count

		times++
	}

	clientServices.EXPECT().
		GetAllSSLKeysAndCertificates(gomock.Any(), gomock.Any()).
		DoAndReturn(func(client *domain.Client, options ...session.ApiOptionsParams) ([]*models.SSLKeyAndCertificate, error) {
			certificates, ok := responses[client.Tenant]
			if ok {
				return certificates, nil
			}

			return nil, fmt.Errorf("%s: That page contains no results", client.Tenant)
		}).
		Times(times)

	return times
}

func setupExpectClientUsage(clientServices *mocks.MockClientServices, times int) {
	clientServices.EXPECT().
		NewClient(gomock.Any(), gomock.Any()).
		DoAndReturn(func(connection *domain.Connection, tenant string) *domain.Client {
			return &domain.Client{
				Connection: connection,
				Tenant:     tenant,
			}
		}).
		Times(times)
	clientServices.EXPECT().
		Connect(gomock.Any()).
		Return(nil).
		Times(times)
	clientServices.EXPECT().
		Close(gomock.Any()).
		Times(times)
}

func setupPost(e *echo.Echo, path string, body io.Reader) (*httptest.ResponseRecorder, echo.Context) {
	request := httptest.NewRequest(http.MethodPost, path, body)
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recorder := httptest.NewRecorder()
	return recorder, e.NewContext(request, recorder)
}

func toPointer(value string) *string {
	clone := strings.Clone(value)
	return &clone
}

func verify(t *testing.T, expecting []*DiscoveredCertificate, recorder *httptest.ResponseRecorder) *DiscoveryPage {
	var err error

	response := recorder.Result() //nolint:bodyclose
	defer func() {
		_ = response.Body.Close()
	}()
	require.NotNil(t, response)
	require.Equal(t, response.StatusCode, http.StatusOK)

	body := recorder.Body.String()
	require.NotNil(t, body)

	results := &DiscoverCertificatesResponse{}
	err = json.Unmarshal([]byte(body), results)
	require.NoError(t, err)

	for _, actual := range results.Messages {
		expected := findDiscoveredCertificate(expecting, actual)
		require.NotNil(t, expected)

		require.Equal(t, len(expected.MachineIdentities), len(actual.MachineIdentities))
		for _, emi := range expected.MachineIdentities {
			matched := false
			for _, ami := range actual.MachineIdentities {
				if !strings.EqualFold(emi.Keystore.Tenant, ami.Keystore.Tenant) ||
					!strings.EqualFold(emi.Keystore.CertificateName, ami.Keystore.CertificateName) ||
					!strings.EqualFold(emi.Binding.VirtualServiceName, ami.Binding.VirtualServiceName) {
					continue
				}

				matched = true
				break
			}

			require.True(t, matched)
		}
	}

	return results.Page
}

func TestDiscovery(t *testing.T) {
	var err error

	e := echo.New()

	t.Run("success_single_page_tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClientServices := mocks.NewMockClientServices(ctrl)

		discoveryServices := NewDiscoveryService(mockClientServices)
		require.NotNil(t, discoveryServices)

		var tdr *tenantDiscoveryResults

		request := &DiscoverCertificatesRequest{
			Configuration: DiscoverCertificatesConfiguration{
				ExcludeExpiredCertificates:  false,
				ExcludeInactiveCertificates: false,
				Tenants:                     "admin",
			},
			Connection: &domain.Connection{
				HostnameOrAddress: "localhost",
				Password:          "password",
				Username:          "user",
			},
			Control: DiscoveryControl{
				MaxResults: 5,
			},
			Page: nil,
		}

		tdr, err = setupDiscovery(t,
			mockClientServices,
			request.Control.MaxResults,
			map[string][]*models.SSLKeyAndCertificate{
				"admin": []*models.SSLKeyAndCertificate{
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nadmin\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * 48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("a"),
						UUID: toPointer("uuid"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid"),
					},
				},
			},
			map[string]map[string][]*models.VirtualService{
				"admin": map[string][]*models.VirtualService{
					"sslkeyandcertificate:uuid": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("vs1"),
						},
						&models.VirtualService{
							Name: toPointer("vs2"),
						},
					},
				},
			})
		require.NotNil(t, tdr)
		require.NoError(t, err)

		var raw []byte
		var recorder *httptest.ResponseRecorder

		raw, err = json.Marshal(request)
		require.NoError(t, err)
		require.NotNil(t, raw)

		var ctx echo.Context

		recorder, ctx = setupPost(e, "/v1/discovercertificates", bytes.NewReader(raw))
		require.NotNil(t, ctx)
		require.NotNil(t, recorder)

		err = discoveryServices.DiscoverCertificates(ctx)
		require.NoError(t, err)

		page := verify(t, tdr.collapse(), recorder)
		require.Nil(t, page)
	})

	t.Run("success_multiple_page_tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClientServices := mocks.NewMockClientServices(ctrl)

		discoveryServices := NewDiscoveryService(mockClientServices)
		require.NotNil(t, discoveryServices)

		var tdr *tenantDiscoveryResults
		var recorder *httptest.ResponseRecorder
		var ctx echo.Context

		request := &DiscoverCertificatesRequest{
			Configuration: DiscoverCertificatesConfiguration{
				ExcludeExpiredCertificates:  false,
				ExcludeInactiveCertificates: false,
				Tenants:                     "admin",
			},
			Connection: &domain.Connection{
				HostnameOrAddress: "localhost",
				Password:          "password",
				Username:          "user",
			},
			Control: DiscoveryControl{
				MaxResults: 2,
			},
			Page: nil,
		}

		tdr, err = setupDiscovery(t,
			mockClientServices,
			request.Control.MaxResults,
			map[string][]*models.SSLKeyAndCertificate{
				"admin": []*models.SSLKeyAndCertificate{
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nadmin-a\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * 48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("a"),
						UUID: toPointer("uuid-a"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-a"),
					},
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nadmin-b\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * 48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("b"),
						UUID: toPointer("uuid-b"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-b"),
					},
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nadmin-c\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * 48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("c"),
						UUID: toPointer("uuid-c"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-c"),
					},
				},
			},
			map[string]map[string][]*models.VirtualService{
				"admin": map[string][]*models.VirtualService{
					"sslkeyandcertificate:uuid-a": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("vs-a1"),
						},
					},
					"sslkeyandcertificate:uuid-b": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("vs-b1"),
						},
						&models.VirtualService{
							Name: toPointer("vs-b2"),
						},
					},
					"sslkeyandcertificate:uuid-c": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("vs-c1"),
						},
						&models.VirtualService{
							Name: toPointer("vs-c2"),
						},
						&models.VirtualService{
							Name: toPointer("vs-c3"),
						},
					},
				},
			})
		require.NotNil(t, tdr)
		require.NoError(t, err)

		var page *DiscoveryPage
		for batch := 0; batch < 2; batch++ {
			if batch > 0 {
				require.NotNil(t, page)
				request.Page = page
			}

			var raw []byte

			raw, err = json.Marshal(request)
			require.NoError(t, err)
			require.NotNil(t, raw)

			recorder, ctx = setupPost(e, "/v1/discovercertificates", bytes.NewReader(raw))
			require.NotNil(t, ctx)
			require.NotNil(t, recorder)

			err = discoveryServices.DiscoverCertificates(ctx)
			require.NoError(t, err)

			page = verify(t, tdr.collapse(), recorder)
		}
	})

	t.Run("success_single_page_multiple_tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClientServices := mocks.NewMockClientServices(ctrl)

		discoveryServices := NewDiscoveryService(mockClientServices)
		require.NotNil(t, discoveryServices)

		var tdr *tenantDiscoveryResults
		var recorder *httptest.ResponseRecorder
		var ctx echo.Context

		request := &DiscoverCertificatesRequest{
			Configuration: DiscoverCertificatesConfiguration{
				ExcludeExpiredCertificates:  false,
				ExcludeInactiveCertificates: false,
				Tenants:                     "admin,Venafi,Swordfish",
			},
			Connection: &domain.Connection{
				HostnameOrAddress: "localhost",
				Password:          "password",
				Username:          "user",
			},
			Control: DiscoveryControl{
				MaxResults: 9,
			},
			Page: nil,
		}

		tdr, err = setupDiscovery(t,
			mockClientServices,
			request.Control.MaxResults,
			map[string][]*models.SSLKeyAndCertificate{
				"admin": []*models.SSLKeyAndCertificate{
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nadmin\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * 48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("a"),
						UUID: toPointer("uuid"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid"),
					},
				},
				"Venafi": []*models.SSLKeyAndCertificate{
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nVenafi1\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * 48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("v-1"),
						UUID: toPointer("uuid-v-1"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-v-1"),
					},
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nVenafi2\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * -48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("v-2"),
						UUID: toPointer("uuid-v-2"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-v-2"),
					},
				},
				"Swordfish": []*models.SSLKeyAndCertificate{
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nSwordfish1\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * 48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("sf-1"),
						UUID: toPointer("uuid-sf-1"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-sf-1"),
					},
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nSwordfish2\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * -48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("sf-2"),
						UUID: toPointer("uuid-sf-2"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-sf-2"),
					},
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nSwordfish3\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * -48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("sf-3"),
						UUID: toPointer("uuid-sf-3"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-sf-3"),
					},
				},
			},
			map[string]map[string][]*models.VirtualService{
				"admin": map[string][]*models.VirtualService{
					"sslkeyandcertificate:uuid": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("a-vs1"),
						},
						&models.VirtualService{
							Name: toPointer("a-vs2"),
						},
					},
				},
				"Venafi": map[string][]*models.VirtualService{
					"sslkeyandcertificate:uuid-v-1": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("v-vs1"),
						},
					},
					"sslkeyandcertificate:uuid-v-2": []*models.VirtualService{},
				},
				"Swordfish": map[string][]*models.VirtualService{
					"sslkeyandcertificate:uuid-sf-1": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("sf-vs1"),
						},
					},
					"sslkeyandcertificate:uuid-sf-2": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("sf-vs2"),
						},
					},
					"sslkeyandcertificate:uuid-sf-3": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("sf-vs3"),
						},
					},
				},
			})
		require.NotNil(t, tdr)
		require.NoError(t, err)

		var raw []byte

		raw, err = json.Marshal(request)
		require.NoError(t, err)
		require.NotNil(t, raw)

		recorder, ctx = setupPost(e, "/v1/discovercertificates", bytes.NewReader(raw))
		require.NotNil(t, ctx)
		require.NotNil(t, recorder)

		err = discoveryServices.DiscoverCertificates(ctx)
		require.NoError(t, err)

		page := verify(t, tdr.collapse(), recorder)
		require.Nil(t, page)
	})

	t.Run("success_multiple_page_multiple_tenant", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClientServices := mocks.NewMockClientServices(ctrl)

		discoveryServices := NewDiscoveryService(mockClientServices)
		require.NotNil(t, discoveryServices)

		var tdr *tenantDiscoveryResults
		var recorder *httptest.ResponseRecorder
		var ctx echo.Context

		request := &DiscoverCertificatesRequest{
			Configuration: DiscoverCertificatesConfiguration{
				ExcludeExpiredCertificates:  false,
				ExcludeInactiveCertificates: false,
				Tenants:                     "admin,Venafi,Swordfish",
			},
			Connection: &domain.Connection{
				HostnameOrAddress: "localhost",
				Password:          "password",
				Username:          "user",
			},
			Control: DiscoveryControl{
				MaxResults: 3,
			},
			Page: nil,
		}

		tdr, err = setupDiscovery(t,
			mockClientServices,
			request.Control.MaxResults,
			map[string][]*models.SSLKeyAndCertificate{
				"admin": []*models.SSLKeyAndCertificate{
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nadmin\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * 48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("a"),
						UUID: toPointer("uuid"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid"),
					},
				},
				"Venafi": []*models.SSLKeyAndCertificate{
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nVenafi1\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * 48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("v-1"),
						UUID: toPointer("uuid-v-1"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-v-1"),
					},
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nVenafi2\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * -48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("v-2"),
						UUID: toPointer("uuid-v-2"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-v-2"),
					},
				},
				"Swordfish": []*models.SSLKeyAndCertificate{
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nSwordfish1\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * 48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("sf-1"),
						UUID: toPointer("uuid-sf-1"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-sf-1"),
					},
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nSwordfish2\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * -48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("sf-2"),
						UUID: toPointer("uuid-sf-2"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-sf-2"),
					},
					&models.SSLKeyAndCertificate{
						Certificate: &models.SSLCertificate{
							Certificate: toPointer("-----BEGIN CERTIFICATE-----\nSwordfish3\n-----END CERTIFICATE-----\n"),
							NotAfter:    toPointer(time.Now().Add(time.Hour * -48).Format(CertificateValidityDateFormat)),
						},
						Name: toPointer("sf-3"),
						UUID: toPointer("uuid-sf-3"),
						URL:  toPointer("https://api/sslkeyandcertificate/sslkeyandcertificate:uuid-sf-3"),
					},
				},
			},
			map[string]map[string][]*models.VirtualService{
				"admin": map[string][]*models.VirtualService{
					"sslkeyandcertificate:uuid": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("a-vs1"),
						},
						&models.VirtualService{
							Name: toPointer("a-vs2"),
						},
					},
				},
				"Venafi": map[string][]*models.VirtualService{
					"sslkeyandcertificate:uuid-v-1": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("v-vs1"),
						},
					},
					"sslkeyandcertificate:uuid-v-2": []*models.VirtualService{},
				},
				"Swordfish": map[string][]*models.VirtualService{
					"sslkeyandcertificate:uuid-sf-1": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("sf-vs1"),
						},
					},
					"sslkeyandcertificate:uuid-sf-2": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("sf-vs2"),
						},
					},
					"sslkeyandcertificate:uuid-sf-3": []*models.VirtualService{
						&models.VirtualService{
							Name: toPointer("sf-vs3"),
						},
					},
				},
			})
		require.NotNil(t, tdr)
		require.NoError(t, err)

		var page *DiscoveryPage
		for batch := 0; batch < 2; batch++ {
			if batch > 0 {
				require.NotNil(t, page)
				request.Page = page
			}

			var raw []byte

			raw, err = json.Marshal(request)
			require.NoError(t, err)
			require.NotNil(t, raw)

			recorder, ctx = setupPost(e, "/v1/discovercertificates", bytes.NewReader(raw))
			require.NotNil(t, ctx)
			require.NotNil(t, recorder)

			err = discoveryServices.DiscoverCertificates(ctx)
			require.NoError(t, err)

			page = verify(t, tdr.collapse(), recorder)
		}
	})
}
