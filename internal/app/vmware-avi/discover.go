package vmwareavi

import (
	"github.com/labstack/echo/v4"
)

// HandleDiscoverCertificates will ...
func (svc *WebhookService) HandleDiscoverCertificates(c echo.Context) error {
	return svc.Discovery.DiscoverCertificates(c)
}
