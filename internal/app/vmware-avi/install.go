package vmwareavi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/vmware/alb-sdk/go/models"
	"github.com/vmware/alb-sdk/go/session"

	"github.com/venafi/vmware-avi-connector/internal/app/domain"
	"go.uber.org/zap"
)

const (
	// SslCertificateTypeCA is the value for a certificate type that is for a certificate authority
	SslCertificateTypeCA = "SSL_CERTIFICATE_TYPE_CA"
	// SslCertificateTypeVirtualService is the value for a certificate type for a virtual service
	SslCertificateTypeVirtualService = "SSL_CERTIFICATE_TYPE_VIRTUALSERVICE"
)

// InstallCertificateBundleRequest contains the request details for installing a certificate, issuing chain and private key
type InstallCertificateBundleRequest struct {
	Connection           *domain.Connection       `json:"connection"`
	CertificateBundle    domain.CertificateBundle `json:"certificateBundle"`
	InstallationKeystore domain.Keystore          `json:"keystore"`
}

// InstallCertificateBundleResponse contains the response for an InstallCertificateBundleRequest
type InstallCertificateBundleResponse struct {
	InstallationKeystore domain.Keystore `json:"keystore"`
}

// HandleInstallCertificateBundle will attempt to install a certificate, issuing chain and private key
func (svc *WebhookServiceImpl) HandleInstallCertificateBundle(c echo.Context) error {
	req := InstallCertificateBundleRequest{}
	if err := c.Bind(&req); err != nil {
		zap.L().Error("invalid request, failed to unmarshall json", zap.Error(err))
		return c.String(http.StatusBadRequest, fmt.Sprintf("failed to unmarshall json: %s", err.Error()))
	}

	var err error

	client := svc.ClientServices.NewClient(req.Connection, req.InstallationKeystore.Tenant)
	err = svc.ClientServices.Connect(client)
	defer func() {
		svc.ClientServices.Close(client)
	}()
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	zap.L().Info("installing certificate bundle on VMware NSX-ALB", zap.String("address", req.Connection.HostnameOrAddress), zap.Int("port", req.Connection.Port))

	err = svc.installCertificateChain(client, &req.InstallationKeystore, req.CertificateBundle.CertificateChain)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	err = svc.installCertificateAndPrivateKey(client, &req.InstallationKeystore, req.CertificateBundle.Certificate, req.CertificateBundle.PrivateKey)
	if err != nil {
		return c.String(http.StatusBadRequest, err.Error())
	}

	// work completed
	zap.L().Info("certificate bundle installed on VMware NSX-ALB", zap.String("address", req.Connection.HostnameOrAddress), zap.Int("port", req.Connection.Port))

	res := InstallCertificateBundleResponse{
		InstallationKeystore: req.InstallationKeystore,
	}

	return c.JSON(http.StatusOK, &res)
}

func (svc *WebhookServiceImpl) installCertificateChain(client *domain.Client, _ *domain.Keystore, chain [][]byte) error {
	var err error

	for _, der := range chain {
		var certificate *x509.Certificate

		certificate, err = parseCertificateDER(der)
		if err != nil {
			return fmt.Errorf("parse chain certificate failed: %w", err)
		}
		var name string
		name, err = getCertificateName(certificate, "")
		if err != nil {
			return fmt.Errorf("read chain certificate name failed: %w", err)
		}

		var kac *models.SSLKeyAndCertificate
		kac, err = svc.ClientServices.GetSSLKeyAndCertificateByName(client, name, session.SetParams(map[string]string{
			"export_key": "false",
		}))
		if err != nil && !strings.EqualFold(fmt.Sprintf("No object of type sslkeyandcertificate with name %s is found", name), err.Error()) {
			return fmt.Errorf(`retrieve chain certificate by name "%s" failed: %w`, name, err)
		}

		if kac != nil {
			if kac.Certificate.Certificate == nil {
				return fmt.Errorf(`retrieve chain certificate by name "%s" failed: empty result`, name)
			}

			var existing *x509.Certificate
			existing, err = parseCertificatePEM([]byte(*kac.Certificate.Certificate))
			if err != nil {
				return fmt.Errorf(`parse chain certificate with name "%s" failed: %w`, name, err)
			}

			if !certificate.Equal(existing) {
				return fmt.Errorf("different chain certificate already exists with the name: %s", name)
			}

			continue
		}

		t := SslCertificateTypeCA
		encoded := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

		create := &models.SSLKeyAndCertificate{
			Certificate: &models.SSLCertificate{
				Certificate: &encoded,
			},
			Name: &name,
			Type: &t,
		}

		_, err = svc.ClientServices.CreateSSLKeyAndCertificate(client, create)
		if err != nil {
			return fmt.Errorf(`failed to install chain certificate with name "%s": %w`, name, err)
		}
	}

	return nil
}

func (svc *WebhookServiceImpl) installCertificateAndPrivateKey(client *domain.Client, keystore *domain.Keystore, certificate, privateKey []byte) error {
	var err error
	var identical bool
	var leaf *x509.Certificate
	var existing *x509.Certificate

	leaf, err = parseCertificateDER(certificate)
	if err != nil {
		return fmt.Errorf("parse certificate failed: %w", err)
	}

	existing, identical, err = svc.isSameCertificate(client, keystore, leaf)
	if err != nil {
		zap.L().Error("failed to check if certificate name exists on VMWare NSX-ALB", zap.Error(err))
		return fmt.Errorf("failed to check if certificate name exists on VMWare NSX-ALB: %s", err.Error())
	}

	if existing != nil {
		if identical {
			return nil
		}

		// generate unique name based on actual certificate
		keystore.CertificateName, err = getCertificateName(leaf, keystore.CertificateName)
		if err != nil {
			return fmt.Errorf("failed to derive unique name for certificate: %w", err)
		}

		existing, identical, err = svc.isSameCertificate(client, keystore, leaf)
		if err != nil {
			zap.L().Error("failed to check if certificate generated name exists on VMWare NSX-ALB", zap.Error(err))
			return fmt.Errorf("failed to check if certificate generated name exists on VMWare NSX-ALB: %s", err.Error())
		}

		if existing != nil {
			if identical {
				return nil
			}

			zap.L().Error("certificate generated name already exists on VMWare NSX-ALB")
			return fmt.Errorf("certificate generated name already exists on VMWare NSX-ALB")
		}
	}

	// TODO: should any other key types be supported?

	t := SslCertificateTypeVirtualService
	encodedCertificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))
	encodedPrivateKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKey}))

	create := &models.SSLKeyAndCertificate{
		Certificate: &models.SSLCertificate{
			Certificate: &encodedCertificate,
		},
		Key:  &encodedPrivateKey,
		Name: &keystore.CertificateName,
		Type: &t,
	}

	_, err = svc.ClientServices.CreateSSLKeyAndCertificate(client, create)
	if err != nil {
		return fmt.Errorf(`failed to install certificate and private key with name "%s": %w`, keystore.CertificateName, err)
	}

	return nil
}

func (svc *WebhookServiceImpl) isSameCertificate(client *domain.Client, keystore *domain.Keystore, certificate *x509.Certificate) (*x509.Certificate, bool, error) {
	var err error
	var kac *models.SSLKeyAndCertificate
	kac, err = svc.ClientServices.GetSSLKeyAndCertificateByName(client, keystore.CertificateName, session.SetParams(map[string]string{
		"export_key": "false",
	}))
	if err != nil && !strings.EqualFold(fmt.Sprintf("No object of type sslkeyandcertificate with name %s is found", keystore.CertificateName), err.Error()) {
		return nil, false, fmt.Errorf(`retrieve certificate by name "%s" failed: %w`, keystore.CertificateName, err)
	}

	if kac != nil {
		if kac.Certificate.Certificate == nil {
			return nil, false, fmt.Errorf(`retrieve certificate by name "%s" failed: empty result`, keystore.CertificateName)
		}

		var existing *x509.Certificate
		existing, err = parseCertificatePEM([]byte(*kac.Certificate.Certificate))
		if err != nil {
			return nil, false, fmt.Errorf(`parse certificate with name "%s" failed: %w`, keystore.CertificateName, err)
		}

		return existing, certificate.Equal(existing), nil
	}

	return nil, false, nil // there is no existing certificate named with value of keystore.CertificateName
}
