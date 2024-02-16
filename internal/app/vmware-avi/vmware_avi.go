package vmwareavi

import (
	"github.com/labstack/echo/v4"
)

// DiscoveryService interfaces for connector discovery functions
type DiscoveryService interface {
	DiscoverCertificates(c echo.Context) error
}

// WebhookServiceImpl implementation of DiscoveryService
type WebhookServiceImpl struct {
	ClientServices ClientServices
	Discovery      DiscoveryService
}

// NewWebhookService will return a new WebhookServiceImpl
func NewWebhookService(clientServices ClientServices, discovery DiscoveryService) *WebhookServiceImpl {
	return &WebhookServiceImpl{
		ClientServices: clientServices,
		Discovery:      discovery,
	}
}
