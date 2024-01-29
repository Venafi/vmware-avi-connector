package vmwareavi

import (
	"github.com/labstack/echo/v4"
)

// DiscoveryService interfaces for connector discovery functions
type DiscoveryService interface {
	DiscoverCertificates(c echo.Context) error
}

// WebhookService implementation of DiscoveryService
type WebhookService struct {
	ClientServices ClientServices
	Discovery      DiscoveryService
}

// NewWebhookService will return a new WebhookService
func NewWebhookService(clientServices ClientServices, discovery DiscoveryService) *WebhookService {
	return &WebhookService{
		ClientServices: clientServices,
		Discovery:      discovery,
	}
}
