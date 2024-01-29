package vmwareavi

import (
	"github.com/labstack/echo/v4"
)

// HandleDiscoverCertificates will attempt to perform a discovery of the VMware AVI certificates and usage
func (svc *WebhookService) HandleDiscoverCertificates(c echo.Context) error {
	return svc.Discovery.DiscoverCertificates(c)
}
