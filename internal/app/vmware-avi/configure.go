package vmwareavi

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/vmware/alb-sdk/go/models"
	"github.com/vmware/alb-sdk/go/session"

	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	"go.uber.org/zap"
)

// ConfigureInstallationEndpointRequest represents ...
type ConfigureInstallationEndpointRequest struct {
	Connection *domain.Connection `json:"connection"`
	Keystore   domain.Keystore    `json:"keystore"`
	Binding    domain.Binding     `json:"binding"`
}

// GetTargetConfigurationRequest represents ...
type GetTargetConfigurationRequest struct {
	Connection *domain.Connection `json:"connection"`
}

// GetTargetConfigurationResponse represents ...
type GetTargetConfigurationResponse struct {
	TargetConfiguration TargetConfiguration `json:"targetConfiguration"`
}

// HandleConfigureInstallationEndpoint ...
func (svc *WebhookService) HandleConfigureInstallationEndpoint(c echo.Context) error {
	req := ConfigureInstallationEndpointRequest{}
	if err := c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshall json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshall json: %s", err.Error()))
	}

	var err error

	client := svc.ClientServices.NewClient(req.Connection, req.Keystore.Tenant)
	err = svc.ClientServices.Connect(client)
	defer func() {
		svc.ClientServices.Close(client)
	}()
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	zap.L().Info("configuring installation endpoint on VMware NSX-ALB", zap.String("address", req.Connection.HostnameOrAddress), zap.Int("port", req.Connection.Port))

	err = svc.configureInstallationEndpoint(client, &req.Binding, &req.Keystore)
	if err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to configure VMware NSX-ALB: %s", err.Error()))
	}

	return c.NoContent(http.StatusOK)
}

// HandleGetTargetConfiguration ...
func (svc *WebhookService) HandleGetTargetConfiguration(c echo.Context) error {
	req := GetTargetConfigurationRequest{}
	if err := c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshall json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshall json: %s", err.Error()))
	}

	res := GetTargetConfigurationResponse{}

	// Future ...

	return c.JSON(http.StatusOK, res)
}

func (svc *WebhookService) configureInstallationEndpoint(client *domain.Client, binding *domain.Binding, keystore *domain.Keystore) error {
	var err error

	// Get the virtual service UUID
	var vs *models.VirtualService
	vs, err = svc.ClientServices.GetVirtualServiceByName(client, binding.VirtualServiceName)
	if err != nil {
		return fmt.Errorf(`failed to retrieve virtual service "%s": %w`, binding.VirtualServiceName, err)
	}

	if vs == nil {
		return fmt.Errorf(`failed to retrieve virtual service "%s": empty response`, binding.VirtualServiceName)
	}

	// Get the certificate UUID
	var kac *models.SSLKeyAndCertificate
	kac, err = svc.ClientServices.GetSSLKeyAndCertificateByName(client, keystore.CertificateName, session.SetParams(map[string]string{
		"export_key": "false",
	}))
	if err != nil {
		return fmt.Errorf(`failed to retrieve certificate "%s": %w`, keystore.CertificateName, err)
	}

	if kac == nil {
		return fmt.Errorf(`failed to retrieve certificate "%s": empty response`, keystore.CertificateName)
	}

	if kac.URL == nil || len(*kac.URL) == 0 {
		return fmt.Errorf(`invalid certificate "%s": no assigned UUID`, keystore.CertificateName)
	}

	// Associate the certificate with the virtual service
	vs.SslKeyAndCertificateRefs = []string{*kac.URL}

	_, err = svc.ClientServices.UpdateVirtualService(client, vs)
	if err != nil {
		return fmt.Errorf(`failed to update the virtual service "%s": %w`, binding.VirtualServiceName, err)
	}

	return nil
}
