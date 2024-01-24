package discovery

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	vmwareavi "github.com/venafi/vmware-avi-connector/internal/app/vmware-avi"
	"github.com/vmware/alb-sdk/go/models"
	"go.uber.org/zap"
)

// DiscoveryService represents ...
type DiscoveryService struct {
	ClientServices vmwareavi.ClientServices
}

// NewDiscoveryService will ...
func NewDiscoveryService(clientServices vmwareavi.ClientServices) *DiscoveryService {
	return &DiscoveryService{
		ClientServices: clientServices,
	}
}

// DiscoverCertificates will ...
func (svc *DiscoveryService) DiscoverCertificates(c echo.Context) error {
	var err error

	req := DiscoverCertificatesRequest{
		Configuration: DiscoverCertificatesConfiguration{
			ExcludeExpiredCertificates:  false,
			ExcludeInactiveCertificates: false,
		},
	}

	if err = c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshall json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshall request json: %s", err.Error()))
	}

	var tenants TenantNames
	if len(req.Configuration.Tenants) == 0 {
		tenants, err = svc.getAllTenants(req.Connection)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
	} else {
		tenants = strings.Split(req.Configuration.Tenants, ",")
		req.Configuration.tenants = make([]string, 0)
		for _, value := range tenants {
			tenant := strings.TrimSpace(value)
			if len(tenant) > 0 && !req.Configuration.tenants.contains(tenant) {
				req.Configuration.tenants = append(req.Configuration.tenants, tenant)
			}
		}
	}

	sort.Slice(tenants, func(i, j int) bool { return lessLower(tenants[i], tenants[j]) })

	csp := newCertificateDiscovery(svc.ClientServices, req.Connection, &req.Configuration, &req.Control)

	if req.Page == nil {
		req.Page = &DiscoveryPage{
			Tenant:    nil,
			Paginator: "",
		}
	}

	var page *DiscoveryPage
	var client *domain.Client

	results := newTenantDiscoveryResults()

	for i, tenant := range tenants {
		if req.Page.Tenant == nil {
			req.Page.Tenant = &tenants[i]
		}

		if !strings.EqualFold(tenant, *req.Page.Tenant) {
			continue
		}

		if client == nil || !strings.EqualFold(client.Tenant, tenant) {
			if client != nil {
				svc.ClientServices.Close(client)
			}

			client = svc.ClientServices.NewClient(req.Connection, tenant)
			err = svc.ClientServices.Connect(client)
			if err != nil {
				return c.String(http.StatusBadRequest, err.Error())
			}
		}

		err = svc.runDiscover(client, &req.Control, csp, req.Page, results)
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}

		if results.Discovered < req.Control.MaxResults {
			req.Page.Tenant = nil
			continue
		}

		break
	}

	if client != nil {
		svc.ClientServices.Close(client)
	}

	page = req.Page
	if req.Page.Tenant == nil {
		page = nil
	}

	return c.JSON(http.StatusOK, buildResponse(page, results))
}

func buildResponse(discoveryPage *DiscoveryPage, discoveredResults *tenantDiscoveryResults) *DiscoverCertificatesResponse {
	discoveredCertificates := discoveredResults.collapse()

	return &DiscoverCertificatesResponse{
		Page:     discoveryPage,
		Messages: discoveredCertificates,
	}
}

func (svc *DiscoveryService) getAllTenants(connection *domain.Connection) (tenants TenantNames, err error) {
	client := svc.ClientServices.NewClient(connection, vmwareavi.DefaultTenantName)
	err = svc.ClientServices.Connect(client)
	defer func() {
		svc.ClientServices.Close(client)
	}()
	if err != nil {
		zap.L().Error("Error connecting to VMware NSX-ALB", zap.String("address", connection.HostnameOrAddress), zap.Int("port", connection.Port), zap.Error(err))
		return nil, fmt.Errorf("failed to connect to VMware NSX-ALB: %w", err)
	}

	var aviTenants []*models.Tenant

	aviTenants, err = svc.ClientServices.GetAllTenants(client)
	if err != nil {
		zap.L().Error("Error reading VMware NSX-ALB tenants", zap.String("address", connection.HostnameOrAddress), zap.Int("port", connection.Port), zap.Error(err))
		return nil, fmt.Errorf("failed to connect to VMware NSX-ALB: %w", err)
	}

	tenants = make(TenantNames, 0, len(aviTenants))
	for _, tenant := range aviTenants {
		if tenant.Name == nil || len(*tenant.Name) == 0 {
			uuid := "no identifier"
			if tenant.UUID != nil && len(*tenant.UUID) > 0 {
				uuid = *tenant.UUID
			}

			zap.L().Info("Skipping empty tenant", zap.String("uuid", uuid))
			continue
		}

		tenants = append(tenants, *tenant.Name)
	}

	return tenants, nil
}
func (svc *DiscoveryService) runDiscover(client *domain.Client, control *DiscoveryControl, csp *certificateDiscoveryProcessor, page *DiscoveryPage, results *tenantDiscoveryResults) error {
	var err error
	var finished bool
	for {
		control.MaxResults -= results.Discovered

		var discovered []*discoveredCertificateAndURL

		finished, discovered, err = csp.discover(client, page)
		if err != nil {
			return err
		}

		control.MaxResults += results.Discovered

		results.append(client.Tenant, discovered)
		discovered = nil

		if !finished && results.Discovered < control.MaxResults {
			continue
		}

		return nil
	}
}
