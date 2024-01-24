package vmwareavi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

func getCertificateName(certificate *x509.Certificate, baseName string) (string, error) {
	var err error
	suffix := ""
	if certificate.SerialNumber.BitLen() > 0 {
		sn := certificate.SerialNumber.String()
		if len(sn) > 4 {
			sn = sn[len(sn)-4:]
		}
		suffix = sn
	}

	if baseName == "" {
		baseName = fmt.Sprintf("%q", certificate.Subject.CommonName)
		baseName, err = normalizeDiacritics(baseName[1 : len(baseName)-1])
		if err != nil {
			return "", fmt.Errorf("unable to read common name: %w", err)
		}
	}

	return fmt.Sprintf("%s-%s-%s", baseName, certificate.NotAfter.Format("060102"), suffix), nil
}

func normalizeDiacritics(input string) (string, error) {
	normalized, _, err := transform.String(norm.NFD, input)
	if err == nil {
		return normalized, nil
	}
	return "", err
}

func parseCertificateDER(content []byte) (*x509.Certificate, error) {
	var err error
	var certificate *x509.Certificate

	certificate, err = x509.ParseCertificate(content)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate: %w", err)
	}

	return certificate, nil
}

func parseCertificatePEM(content []byte) (*x509.Certificate, error) {
	var block *pem.Block

	remaining := make([]byte, len(content))
	copy(remaining, content)

	for {
		block, _ = pem.Decode(remaining)
		if block == nil {
			break
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing TLS certificate: %s", err)
		}

		return cert, nil
	}

	return nil, nil
}
