// Package discovery implements logic for paged certificate discovery on a VMware AVI host
package discovery

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	vmwareavi "github.com/venafi/vmware-avi-connector/internal/app/vmware-avi"
	"github.com/vmware/alb-sdk/go/models"
	"github.com/vmware/alb-sdk/go/session"
	"go.uber.org/zap"
)

const (
	// DefaultPageSize is the constant representing the number of results per paged request to VMware
	DefaultPageSize = 10
	// DefaultCertificateSearch will include only system and virtual service certificates -- excluding CA certificates
	DefaultCertificateSearch = "(type,SSL_CERTIFICATE_TYPE_SYSTEM)|(type,SSL_CERTIFICATE_TYPE_VIRTUALSERVICE)"
)

type certificateDiscoveryPaginator struct {
	Page  int `json:"page"`
	Index int `json:"index"`
}

type certificateDiscoveryProcessor struct {
	caCertificates map[string]string
	connection     *domain.Connection
	configuration  *DiscoverCertificatesConfiguration
	control        *DiscoveryControl
	paginator      *certificateDiscoveryPaginator
	clientServices vmwareavi.ClientServices
}

func newCertificateDiscovery(services vmwareavi.ClientServices, connection *domain.Connection, configuration *DiscoverCertificatesConfiguration, control *DiscoveryControl) *certificateDiscoveryProcessor {
	return &certificateDiscoveryProcessor{
		caCertificates: map[string]string{},
		connection:     connection,
		configuration:  configuration,
		control:        control,
		paginator: &certificateDiscoveryPaginator{
			Page:  1,
			Index: 0,
		},
		clientServices: services,
	}
}

func (p *certificateDiscoveryProcessor) addCaCertificates(client *domain.Client, certificateName string, caCerts []*models.CertificateAuthority, dc *DiscoveredCertificate) {
	if len(caCerts) == 0 {
		return
	}

	var err error

	chain := make([]string, len(caCerts))
	for idx, caCert := range caCerts {
		if caCert == nil {
			zap.L().Info("null CA Certificate in collection", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", certificateName))
			return
		}

		if caCert.CaRef == nil {
			if caCert.Name == nil || len(*caCert.Name) == 0 {
				zap.L().Info("missing CA Certificate reference", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", certificateName))
				return
			}

			var caCert2 *models.SSLKeyAndCertificate

			caCert2, err = p.clientServices.GetSSLKeyAndCertificateByName(client, *caCert.Name, session.SetParams(map[string]string{
				"export_key": "false",
			}))
			if err != nil {
				zap.L().Info("failed to retrieve CA Certificate by name", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", certificateName), zap.String("caCertificateName", *caCert.Name))
				return
			}

			caCert.CaRef = caCert2.URL
		}

		var id string
		id, err = getUUIDFromURL(*caCert.CaRef)
		if err != nil {
			zap.L().Info("unable to parse CA Certificate reference", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", certificateName), zap.Error(err))
			return
		}

		var exists bool
		var pem string
		pem, exists = p.caCertificates[*caCert.CaRef]
		if exists {
			chain[idx] = pem
			continue
		}

		var cac *models.SSLKeyAndCertificate
		cac, err = p.clientServices.GetSSLKeyAndCertificateByID(client, id)
		if err != nil {
			zap.L().Info("failed to retrieve CA Certificate by reference", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", certificateName), zap.String("reference", *caCert.CaRef), zap.Error(err))
			return
		}

		if cac == nil || cac.Certificate == nil || cac.Certificate.Certificate == nil {
			zap.L().Info("CA Certificate reference has no pem", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", certificateName), zap.String("reference", *caCert.CaRef))
			return
		}

		if len(*cac.Certificate.Certificate) == 0 {
			zap.L().Info("CA Certificate reference has empty pem", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", certificateName), zap.String("reference", *caCert.CaRef))
			return
		}

		chain[idx] = *cac.Certificate.Certificate
		p.caCertificates[*caCert.CaRef] = *cac.Certificate.Certificate
	}

	dc.CertificateChain = chain
}

func (p *certificateDiscoveryProcessor) discover(client *domain.Client, page *DiscoveryPage) (finished bool, results []*discoveredCertificateAndURL, err error) {
	if !strings.EqualFold(client.Tenant, *page.Tenant) {
		page.Paginator = ""
		return true, nil, nil
	}

	if len(page.Paginator) > 0 {
		err = json.Unmarshal([]byte(page.Paginator), p.paginator)
		if err != nil {
			page.Paginator = ""

			zap.L().Error("failed to unmarshal the certificate discovery page paginator", zap.String("address", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.Error(err))
			return true, nil, fmt.Errorf("failed to unmarshal certificate discovery page paginator: %w", err)
		}
	}

	discoveredCertificates := make([]*discoveredCertificateAndURL, 0)

	for {
		var ok bool
		var certificates []*models.SSLKeyAndCertificate

		certificates, err = p.clientServices.GetAllSSLKeysAndCertificates(client, session.SetParams(map[string]string{
			"export_key": "false",
			"page":       strconv.Itoa(p.paginator.Page),
			"page_size":  strconv.Itoa(DefaultPageSize),
			"search":     DefaultCertificateSearch,
		}))
		if err != nil {
			var ae session.AviError

			ae, ok = err.(session.AviError)
			if !ok || ae.AviResult.Message == nil || !strings.Contains(*ae.AviResult.Message, "That page contains no results") {
				page.Paginator = ""

				zap.L().Error("Error reading VMware NSX-ALB certificates", zap.String("address", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.Error(err))
				return true, nil, fmt.Errorf(`failed to read VMware NSX-ALB certificates for the tenant "%s": %w`, client.Tenant, err)
			}

			p.paginator.Page = 1
			p.paginator.Index = 0
			break
		}

		for p.paginator.Index < len(certificates) {
			cert := certificates[p.paginator.Index]
			p.paginator.Index++

			if cert == nil {
				continue
			}

			if cert.Name == nil {
				zap.L().Info("skipping certificate with no name", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", getCertificateName(cert)))
				continue
			}

			certificate := cert.Certificate
			if certificate == nil {
				zap.L().Info("skipping certificate with no certificate content", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", getCertificateName(cert)))
				continue
			}

			if p.configuration.ExcludeExpiredCertificates {
				var expired bool
				expired, err = isExpired(certificate)
				if err != nil {
					zap.L().Info("skipping  discoveredCertificates certificate with un-parsable not after", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", getCertificateName(cert)), zap.String("notAfter", getValue(certificate.NotAfter)))
					continue
				}

				if expired {
					zap.L().Info("skipping expired certificate", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", getCertificateName(cert)))
					continue
				}
			}

			if certificate.Certificate == nil {
				zap.L().Info("skipping certificate with no pem", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", getCertificateName(cert)))
				continue
			}

			zap.L().Info("discoveredCertificates certificate", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", getCertificateName(cert)))

			dc := &DiscoveredCertificate{
				Certificate:       *certificate.Certificate,
				CertificateChain:  make([]string, 0),
				Installations:     make([]*CertificateInstallation, 0),
				MachineIdentities: make([]*MachineIdentity, 0),
			}

			p.addCaCertificates(client, getCertificateName(cert), cert.CaCerts, dc)

			var uuid string
			if cert.UUID != nil {
				uuid = *cert.UUID
			} else if cert.URL != nil {
				uuid, err = getUUIDFromURL(*cert.URL)
				if err != nil {
					zap.L().Info("skipping certificate with invalid url", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", getCertificateName(cert)), zap.Error(err))
					continue
				}
			} else {
				zap.L().Info("skipping certificate with no uuid or url", zap.String("hostname", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.String("name", getCertificateName(cert)))
				continue
			}

			dcr := &discoveredCertificateAndURL{
				Name:   getCertificateName(cert),
				Result: dc,
				UUID:   uuid,
			}

			err = processVirtualServices(client, p.clientServices, dcr)
			if err != nil {
				_ = p.updateDiscoveryPaginator(client, true, page)
				return true, nil, err
			}

			if !p.configuration.ExcludeInactiveCertificates || len(dcr.Result.MachineIdentities) > 0 {
				discoveredCertificates = append(discoveredCertificates, dcr)

				if len(discoveredCertificates) >= p.control.MaxResults {
					finished = false

					err = p.updateDiscoveryPaginator(client, finished, page)
					return finished, discoveredCertificates, err
				}
			}
		}

		p.paginator.Index = 0

		if len(certificates) == DefaultPageSize {
			p.paginator.Page++
			continue
		}

		p.paginator.Page = 1
		break
	}

	finished = true

	err = p.updateDiscoveryPaginator(client, finished, page)
	return finished, discoveredCertificates, err
}

func (p *certificateDiscoveryProcessor) updateDiscoveryPaginator(client *domain.Client, finished bool, page *DiscoveryPage) error {
	if !finished {
		data, err := json.Marshal(p.paginator)
		if err != nil {
			zap.L().Error("Error marshalling VMware NSX-ALB discovery page", zap.String("address", p.connection.HostnameOrAddress), zap.Int("port", p.connection.Port), zap.String("tenant", client.Tenant), zap.Error(err))
			return fmt.Errorf(`failed to marshal VMware NSX-ALB discovery page for the tenant "%s": %w`, client.Tenant, err)
		}

		page.Paginator = string(data)
		return nil
	}

	page.Paginator = ""
	return nil
}
