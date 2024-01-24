package discovery

import "github.com/venafi/vmware-avi-connector/internal/app/domain"

type discoveredCertificateAndURL struct {
	Name   string
	Result *DiscoveredCertificate
	UUID   string
}

// DiscoveryControl represents the Venafi defined definitions for discovery result processing
type DiscoveryControl struct {
	MaxResults int `json:"maxResults"`
}

// DiscoverCertificatesConfiguration represents the discovery configuration settings defined by the administrator
type DiscoverCertificatesConfiguration struct {
	ExcludeExpiredCertificates  bool   `json:"excludeExpiredCertificates"`
	ExcludeInactiveCertificates bool   `json:"excludeInactiveCertificates"`
	Tenants                     string `json:"tenants"`

	tenants TenantNames
}

// DiscoverCertificatesRequest ...
type DiscoverCertificatesRequest struct {
	Configuration DiscoverCertificatesConfiguration `json:"discovery"`
	Connection    *domain.Connection                `json:"connection"`
	Control       DiscoveryControl                  `json:"discoveryControl"`
	Page          *DiscoveryPage                    `json:"discoveryPage,omitempty"`
}

// DiscoveryPage is a Venafi allowed construct that represents the current pagination state of an active discovery
type DiscoveryPage struct {
	Tenant    *string `json:"discoveryType,omitempty"`
	Paginator string  `json:"paginator"`
}

// DiscoverCertificatesResponse represents the response to a discovery request
type DiscoverCertificatesResponse struct {
	Page     *DiscoveryPage           `json:"discoveryPage"`
	Messages []*DiscoveredCertificate `json:"messages"`
}

// DiscoveredCertificate represents a single certificate and it's usage found during a discovery
type DiscoveredCertificate struct {
	Certificate       string                     `json:"certificate"`
	CertificateChain  []string                   `json:"certificateChain"` // root last ...
	Installations     []*CertificateInstallation `json:"installations"`
	MachineIdentities []*MachineIdentity         `json:"machineIdentities"`
}

// CertificateInstallation represents usage of a discovered certificate
type CertificateInstallation struct {
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ipAddress"`
	Port      int    `json:"port"`
}

// MachineIdentity represents a certificate being used as found during a discovery
type MachineIdentity struct {
	Keystore *domain.Keystore `json:"keystore"`
	Binding  *domain.Binding  `json:"binding"`
}
