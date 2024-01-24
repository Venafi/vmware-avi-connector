package vmwareavi

import (
	"github.com/labstack/echo/v4"
)

// DiscoveryService represents ...
type DiscoveryService interface {
	DiscoverCertificates(c echo.Context) error
}

// WebhookService ...
type WebhookService struct {
	ClientServices ClientServices
	Discovery      DiscoveryService
}

// NewWebhookService will return a new service
func NewWebhookService(clientServices ClientServices, discovery DiscoveryService) *WebhookService {
	return &WebhookService{
		ClientServices: clientServices,
		Discovery:      discovery,
	}
}
