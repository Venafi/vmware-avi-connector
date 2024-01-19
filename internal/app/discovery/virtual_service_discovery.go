package discovery

import (
	"fmt"

	vmware_avi "github.com/venafi/vmware-avi-connector/internal/app/vmware-avi"

	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	"github.com/vmware/alb-sdk/go/models"
	"github.com/vmware/alb-sdk/go/session"
	"go.uber.org/zap"
)

func processVirtualServices(client *domain.Client, clientServices vmware_avi.ClientServices, dcr *discoveredCertificateAndURL) error {
	var err error
	var virtualServices []*models.VirtualService

	virtualServices, err = clientServices.GetAllVirtualServices(client, session.SetParams(map[string]string{
		"refers_to": fmt.Sprintf("sslkeyandcertificate:%s", dcr.UUID),
	}))
	if err != nil {
		zap.L().Info("failed to read virtual services for certificate", zap.String("hostname", client.Connection.HostnameOrAddress), zap.Int("port", client.Connection.Port), zap.String("tenant", client.Tenant), zap.String("certificateName", dcr.Name))
		return err
	}

	for _, vs := range virtualServices {
		zap.L().Info("discovered virtual service for tenant and certificate", zap.String("hostname", client.Connection.HostnameOrAddress), zap.Int("port", client.Connection.Port), zap.String("tenant", client.Tenant), zap.String("certificateName", dcr.Name), zap.String("virtualService", getVirtualServiceName(vs)))

		if vs.Name == nil {
			zap.L().Info("skipping virtual services with no name for certificate", zap.String("hostname", client.Connection.HostnameOrAddress), zap.Int("port", client.Connection.Port), zap.String("tenant", client.Tenant), zap.String("certificateName", dcr.Name))
			continue
		}

		mi := &MachineIdentity{
			Keystore: &domain.Keystore{
				CertificateName: dcr.Name,
				Tenant:          client.Tenant,
			},
			Binding: &domain.Binding{
				VirtualServiceName: *vs.Name,
			},
		}

		dcr.Result.MachineIdentities = append(dcr.Result.MachineIdentities, mi)
	}

	return nil
}
