package vmwareavi

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	"go.uber.org/zap"
)

// TestConnectionRequest contains the request details for testing connectivity with a VMware AVI host
type TestConnectionRequest struct {
	Connection *domain.Connection `json:"connection"`
}

// TestConnectionResponse contains the response for a TestConnectionRequest
type TestConnectionResponse struct {
	Result bool `json:"result"`
}

// HandleTestConnection will attempt to connect to a VMware AVI host
func (svc *WebhookService) HandleTestConnection(c echo.Context) error {
	var err error

	req := TestConnectionRequest{}
	if err = c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshall json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshall json: %s", err.Error()))
	}

	res := TestConnectionResponse{
		Result: false,
	}

	client := svc.ClientServices.NewClient(req.Connection, "")
	err = svc.ClientServices.Connect(client)
	defer func() {
		svc.ClientServices.Close(client)
	}()
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	res.Result = true
	zap.L().Info("Success connecting to VMware NSX-ALB", zap.String("address", req.Connection.HostnameOrAddress), zap.Int("port", req.Connection.Port))
	return c.JSON(http.StatusOK, res)
}
