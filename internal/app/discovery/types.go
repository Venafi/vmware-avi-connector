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

// DiscoverCertificatesConfiguration represents the discovery configuration settings defined by the manifest.json
type DiscoverCertificatesConfiguration struct {
	ExcludeExpiredCertificates  bool   `json:"excludeExpiredCertificates"`
	ExcludeInactiveCertificates bool   `json:"excludeInactiveCertificates"`
	Tenants                     string `json:"tenants"`

	tenants TenantNames
}

// DiscoverCertificatesRequest contains the request details for a discovery
type DiscoverCertificatesRequest struct {
	Configuration DiscoverCertificatesConfiguration `json:"discovery"`
	Connection    *domain.Connection                `json:"connection"`
	Control       DiscoveryControl                  `json:"discoveryControl"`
	Page          *DiscoveryPage                    `json:"discoveryPage,omitempty"`
}

// DiscoveryPage represents the current pagination state of an active discovery as defined by the discoveryPage
// definition in the manifest.json.
type DiscoveryPage struct {
	// The name of the tenant to start at when continuing the next discovery request
	Tenant *string `json:"discoveryType,omitempty"`
	// The value for using when continuing the next discovery request.  This value is defined by the connector.
	Paginator string `json:"paginator"`
}

// DiscoverCertificatesResponse represents the response to a discovery request
type DiscoverCertificatesResponse struct {
	// The current pagination state for the current discovery request.
	// If the discovery is completed in the current discovery request then this value should be nil.
	Page *DiscoveryPage `json:"discoveryPage"`
	// The certificates and usage discovered during the current discovery request.
	Messages []*DiscoveredCertificate `json:"messages"`
}

// DiscoveredCertificate is a Venafi defined struct that represents a single certificate and it's usage found during a discovery
type DiscoveredCertificate struct {
	// The raw certificate bytes as a base64 encoded string
	Certificate string `json:"certificate"`
	// The issuing chain of certificates ordered from the last intermediate issuing certificate to the root CA certificate
	CertificateChain []string `json:"certificateChain"`
	// The collection of virtual services using the certificate
	Installations []*CertificateInstallation `json:"installations"`
	// The collection of machine identities for the certificate
	MachineIdentities []*MachineIdentity `json:"machineIdentities"`
}

// CertificateInstallation is a Venafi defined struct that represents usage of a discovered certificate
type CertificateInstallation struct {
	// The hostname or IP Address
	Hostname string `json:"hostname"`
	// The IP Address
	IPAddress string `json:"ipAddress"`
	// The port number
	Port int `json:"port"`
}

// MachineIdentity is a Venafi defined struct that represents a certificate usage as found during a discovery
type MachineIdentity struct {
	// The keystore values for a certificate as defined in the manifest.json
	Keystore *domain.Keystore `json:"keystore"`
	// The binding values for a certificate as defined in the manifest.json
	Binding *domain.Binding `json:"binding"`
}
