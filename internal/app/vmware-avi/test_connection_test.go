package vmware_avi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	"github.com/venafi/vmware-avi-connector/internal/app/vmware-avi/mocks"
)

func TestConnectionTest(t *testing.T) {
	var err error

	e := echo.New()

	t.Parallel()

	t.Run("success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockClientServices := mocks.NewMockClientServices(ctrl)

		whService := NewWebhookService(mockClientServices, nil)
		require.NotNil(t, whService)

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

		var raw []byte

		raw, err = json.Marshal(&TestConnectionRequest{
			Connection: &domain.Connection{
				HostnameOrAddress: "localhost",
				Password:          "password",
				Port:              443,
				Username:          "user",
			},
		})
		require.NoError(t, err)
		require.NotNil(t, raw)

		recorder, ctx := setupPost(e, "/v1/testconnection", bytes.NewReader(raw))
		require.NotNil(t, ctx)
		require.NotNil(t, recorder)

		err = whService.HandleTestConnection(ctx)
		require.NoError(t, err)

		response := recorder.Result() //nolint:bodyclose
		defer func() {
			_ = response.Body.Close()
		}()
		require.NotNil(t, response)
		require.Equal(t, response.StatusCode, http.StatusOK)

		body := recorder.Body.String()
		require.NotNil(t, body)

		tcr := &TestConnectionResponse{}
		err = json.Unmarshal([]byte(body), tcr)
		require.NoError(t, err)
		require.True(t, tcr.Result)
	})
}

func setupPost(e *echo.Echo, path string, body io.Reader) (*httptest.ResponseRecorder, echo.Context) {
	request := httptest.NewRequest(http.MethodPost, path, body)
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recorder := httptest.NewRecorder()
	return recorder, e.NewContext(request, recorder)
}
