package vmwareavi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	"github.com/venafi/vmware-avi-connector/internal/app/vmware-avi/mocks"
	"github.com/vmware/alb-sdk/go/models"
	"github.com/vmware/alb-sdk/go/session"
	"go.uber.org/mock/gomock"
)

func TestConfigure(t *testing.T) {
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

		raw, err = json.Marshal(&ConfigureInstallationEndpointRequest{
			Connection: &domain.Connection{
				HostnameOrAddress: "localhost",
				Password:          "password",
				Port:              443,
				Username:          "user",
			},
			Keystore: domain.Keystore{
				CertificateName: "installation.test.io",
				Tenant:          "test",
			},
			Binding: domain.Binding{
				VirtualServiceName: "vstest",
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
			GetVirtualServiceByName(gomock.Any(), gomock.Eq("vstest")).
			DoAndReturn(func(client *domain.Client, name string, options ...session.ApiOptionsParams) (*models.VirtualService, error) {
				vsn := name
				vsUUID := "virtualservice:" + uuid.New().String()

				vs := &models.VirtualService{
					Name:                     &vsn,
					SslKeyAndCertificateRefs: []string{"sslkeyandcertificate:old"},
					UUID:                     &vsUUID,
				}
				return vs, nil
			})

		kacn := "installation.test.io"
		kacURL := "https://localhost/api/virtualservice/" + kacn

		mockClientServices.EXPECT().
			GetSSLKeyAndCertificateByName(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(client *domain.Client, name string, options ...session.ApiOptionsParams) (*models.SSLKeyAndCertificate, error) {
				kac := &models.SSLKeyAndCertificate{
					Name: &kacn,
					URL:  &kacURL,
				}
				return kac, nil
			})

		mockClientServices.EXPECT().
			UpdateVirtualService(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(client *domain.Client, obj *models.VirtualService, options ...session.ApiOptionsParams) (*models.VirtualService, error) {
				require.NotNil(t, obj)
				require.True(t, len(obj.SslKeyAndCertificateRefs) == 1)
				require.Equal(t, kacURL, obj.SslKeyAndCertificateRefs[0])
				return obj, nil
			})

		err = whService.HandleConfigureInstallationEndpoint(ctx)
		require.NoError(t, err)

		response := recorder.Result() // nolint:bodyclose
		defer func() {
			_ = response.Body.Close()
		}()
		require.NotNil(t, response)
		require.Equal(t, response.StatusCode, http.StatusOK)

		body := recorder.Body.String()
		require.NotNil(t, body)
		require.True(t, len(body) == 0)
	})
}
