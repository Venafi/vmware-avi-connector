// Package vmwareavi contains logic specific for working with VMware AVI devices
package vmwareavi

import (
	"errors"
	"fmt"

	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	"github.com/vmware/alb-sdk/go/clients"
	"github.com/vmware/alb-sdk/go/models"
	"github.com/vmware/alb-sdk/go/session"
	"go.uber.org/zap"
)

//go:generate go run go.uber.org/mock/mockgen -source ./client.go -destination=./mocks/mock_client.go -package=mocks

// ClientServices interfaces for interacting with VMware AVI
type ClientServices interface {
	// Close will ...
	Close(client *domain.Client)
	// Connect will ...
	Connect(client *domain.Client) error
	// CreateSSLKeyAndCertificate will create a new SSLKeyAndCertificate object
	CreateSSLKeyAndCertificate(client *domain.Client, obj *models.SSLKeyAndCertificate, options ...session.ApiOptionsParams) (*models.SSLKeyAndCertificate, error)
	// GetAllSSLKeysAndCertificates will return a collection of SSLKeyAndCertificate objects
	GetAllSSLKeysAndCertificates(client *domain.Client, options ...session.ApiOptionsParams) ([]*models.SSLKeyAndCertificate, error)
	// GetAllTenants will return a collection of Tenant objects
	GetAllTenants(client *domain.Client, options ...session.ApiOptionsParams) ([]*models.Tenant, error)
	// GetAllVirtualServices will return a collection of VirtualService objects
	GetAllVirtualServices(client *domain.Client, options ...session.ApiOptionsParams) ([]*models.VirtualService, error)
	// GetSSLKeyAndCertificateById will return an existing SSLKeyAndCertificate by name
	GetSSLKeyAndCertificateByID(client *domain.Client, uuid string, options ...session.ApiOptionsParams) (*models.SSLKeyAndCertificate, error)
	// GetSSLKeyAndCertificateByName will return an existing SSLKeyAndCertificate by name
	GetSSLKeyAndCertificateByName(client *domain.Client, name string, options ...session.ApiOptionsParams) (*models.SSLKeyAndCertificate, error)
	// GetVirtualServiceByName will return an existing VirtualService by name
	GetVirtualServiceByName(client *domain.Client, name string, options ...session.ApiOptionsParams) (*models.VirtualService, error)
	// NewClient will create a new client instance
	NewClient(connection *domain.Connection, tenant string) *domain.Client
	// UpdateVirtualService will update an existing VirtualService object
	UpdateVirtualService(client *domain.Client, obj *models.VirtualService, options ...session.ApiOptionsParams) (*models.VirtualService, error)
}

// VMwareAviClientsImpl implementation of ClientServices
type VMwareAviClientsImpl struct {
}

// NewVMwareAviClients will return a new VMware AVI client
func NewVMwareAviClients() *VMwareAviClientsImpl {
	return &VMwareAviClientsImpl{}
}

// Close will logout the client session
func (c *VMwareAviClientsImpl) Close(client *domain.Client) {
	if client == nil || client.Session == nil {
		return
	}

	unwrapped, ok := client.Session.(clients.AviClient)
	if !ok {
		return
	}

	_ = unwrapped.AviSession.Logout()
	client.Session = nil
}

// Connect will attempt to create a new client session and connect to the VMware AVI host
func (c *VMwareAviClientsImpl) Connect(client *domain.Client) error {
	var err error

	zap.L().Info("attempting to connect to VMware NSX-ALB", zap.String("address", client.Connection.HostnameOrAddress), zap.Int("port", client.Connection.Port))

	var tc *clients.AviClient

	tc, err = clients.NewAviClient(client.Connection.HostnameOrAddress, client.Connection.Username,
		session.SetPassword(client.Connection.Password),
		session.SetInsecure)
	if err != nil {
		zap.L().Error("failed to connect to the VMware NSX-ALB host", zap.String("hostname", client.Connection.HostnameOrAddress), zap.Int("port", client.Connection.Port), zap.Error(err))
		return fmt.Errorf("failed to connect: %w", err)
	}

	version, err := tc.AviSession.GetControllerVersion()
	if err != nil {
		zap.L().Error("failed reading the VMware NSX-ALB host version", zap.String("hostname", client.Connection.HostnameOrAddress), zap.Int("port", client.Connection.Port), zap.Error(err))
		return fmt.Errorf("failed reading the VMware NSX-ALB host version: %w", err)
	}

	if len(version) == 0 {
		err = errors.New("empty response data")
		zap.L().Error("failed reading the VMware NSX-ALB host version", zap.String("hostname", client.Connection.HostnameOrAddress), zap.Int("port", client.Connection.Port), zap.Error(err))
		return fmt.Errorf("failed reading the VMware NSX-ALB host version: %w", err)
	}

	_ = tc.AviSession.Logout()

	tc, err = clients.NewAviClient(client.Connection.HostnameOrAddress, client.Connection.Username,
		session.SetPassword(client.Connection.Password),
		session.SetTenant(client.Tenant),
		session.SetVersion(version),
		session.SetInsecure)
	if err != nil {
		zap.L().Error("failed to connect to the VMware NSX-ALB host with tenant", zap.String("hostname", client.Connection.HostnameOrAddress), zap.Int("port", client.Connection.Port), zap.String("tenant", client.Tenant), zap.Error(err))
		return fmt.Errorf(`failed to connect with tenant "%s": %w`, client.Tenant, err)
	}

	client.Session = tc
	return nil
}

// CreateSSLKeyAndCertificate will create a new SSLKeyAndCertificate object
func (c *VMwareAviClientsImpl) CreateSSLKeyAndCertificate(client *domain.Client, obj *models.SSLKeyAndCertificate, options ...session.ApiOptionsParams) (*models.SSLKeyAndCertificate, error) {
	unwrapped, ok := client.Session.(*clients.AviClient)
	if !ok {
		return nil, errors.New("invalid session")
	}

	return unwrapped.SSLKeyAndCertificate.Create(obj, options...)
}

// GetAllSSLKeysAndCertificates will return a collection of SSLKeyAndCertificate objects
func (c *VMwareAviClientsImpl) GetAllSSLKeysAndCertificates(client *domain.Client, options ...session.ApiOptionsParams) ([]*models.SSLKeyAndCertificate, error) {
	unwrapped, ok := client.Session.(*clients.AviClient)
	if !ok {
		return nil, errors.New("invalid session")
	}

	return unwrapped.SSLKeyAndCertificate.GetAll(options...)
}

// GetAllTenants will return a collection of Tenant objects
func (c *VMwareAviClientsImpl) GetAllTenants(client *domain.Client, options ...session.ApiOptionsParams) ([]*models.Tenant, error) {
	unwrapped, ok := client.Session.(*clients.AviClient)
	if !ok {
		return nil, errors.New("invalid session")
	}

	return unwrapped.Tenant.GetAll(options...)
}

// GetAllVirtualServices will return a collection of VirtualService objects
func (c *VMwareAviClientsImpl) GetAllVirtualServices(client *domain.Client, options ...session.ApiOptionsParams) ([]*models.VirtualService, error) {
	unwrapped, ok := client.Session.(*clients.AviClient)
	if !ok {
		return nil, errors.New("invalid session")
	}

	return unwrapped.VirtualService.GetAll(options...)
}

// GetSSLKeyAndCertificateByID will return an existing SSLKeyAndCertificate by name
func (c *VMwareAviClientsImpl) GetSSLKeyAndCertificateByID(client *domain.Client, uuid string, options ...session.ApiOptionsParams) (*models.SSLKeyAndCertificate, error) {
	unwrapped, ok := client.Session.(*clients.AviClient)
	if !ok {
		return nil, errors.New("invalid session")
	}

	return unwrapped.SSLKeyAndCertificate.Get(uuid, options...)
}

// GetSSLKeyAndCertificateByName will return an existing SSLKeyAndCertificate by name
func (c *VMwareAviClientsImpl) GetSSLKeyAndCertificateByName(client *domain.Client, name string, options ...session.ApiOptionsParams) (*models.SSLKeyAndCertificate, error) {
	unwrapped, ok := client.Session.(*clients.AviClient)
	if !ok {
		return nil, errors.New("invalid session")
	}

	return unwrapped.SSLKeyAndCertificate.GetByName(name, options...)
}

// GetVirtualServiceByName will return an existing VirtualService by name
func (c *VMwareAviClientsImpl) GetVirtualServiceByName(client *domain.Client, name string, options ...session.ApiOptionsParams) (*models.VirtualService, error) {
	unwrapped, ok := client.Session.(*clients.AviClient)
	if !ok {
		return nil, errors.New("invalid session")
	}

	return unwrapped.VirtualService.GetByName(name, options...)
}

// NewClient will create a new client instance
func (c *VMwareAviClientsImpl) NewClient(connection *domain.Connection, tenant string) *domain.Client {
	if connection.Port == 0 {
		connection.Port = 443
	}

	if len(tenant) == 0 {
		tenant = DefaultTenantName
	}

	return &domain.Client{
		Connection: connection,
		Session:    nil,
		Tenant:     tenant,
	}
}

// UpdateVirtualService will update an existing VirtualService object
func (c *VMwareAviClientsImpl) UpdateVirtualService(client *domain.Client, obj *models.VirtualService, options ...session.ApiOptionsParams) (*models.VirtualService, error) {
	unwrapped, ok := client.Session.(*clients.AviClient)
	if !ok {
		return nil, errors.New("invalid session")
	}

	return unwrapped.VirtualService.Update(obj, options...)
}
