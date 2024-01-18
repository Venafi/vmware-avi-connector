package vmware_avi

import (
	"github.com/labstack/echo/v4"
)

func (svc *WebhookService) HandleDiscoverCertificates(c echo.Context) error {
	return svc.Discovery.DiscoverCertificates(c)
}
