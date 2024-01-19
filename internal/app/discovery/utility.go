package discovery

import (
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vmware/alb-sdk/go/models"
)

// TenantNames represents ...
type TenantNames []string

func (tenants TenantNames) contains(tenant string) bool {
	for _, name := range tenants {
		if strings.Compare(tenant, name) == 0 {
			return true
		}
	}

	return false
}

func getCertificateName(certificate *models.SSLKeyAndCertificate) string {
	if certificate == nil {
		return "nil"
	}

	if certificate.Name != nil {
		return *certificate.Name
	}

	if certificate.UUID != nil {
		return *certificate.UUID
	}

	if certificate.URL != nil {
		id, err := getUUIDFromURL(*certificate.URL)
		if err == nil {
			return id
		}
	}

	return "missing name"
}

func getUUIDFromURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse entity URL \"%s\": %w", rawURL, err)
	}

	path := strings.TrimSpace(u.Path)
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")

	components := strings.Split(path, "/")
	return components[len(components)-1], nil
}

func getValue(value *string) string {
	if value == nil {
		return "nil"
	}

	if len(*value) == 0 {
		return "empty"
	}

	return *value
}

func getVirtualServiceName(virtualService *models.VirtualService) string {
	if virtualService == nil {
		return "nil"
	}

	if virtualService.Name != nil {
		return *virtualService.Name
	}

	if virtualService.UUID != nil {
		return *virtualService.UUID
	}

	if virtualService.URL != nil {
		id, err := getUUIDFromURL(*virtualService.URL)
		if err == nil {
			return id
		}
	}

	return "missing name"
}

func isExpired(certificate *models.SSLCertificate) (expired bool, err error) {
	notAfter := getValue(certificate.NotAfter)
	if len(notAfter) == 0 {
		return false, fmt.Errorf("no certificate expiration value")
	}

	t, err := time.Parse("2006-01-02 15:04:05", notAfter)
	if err != nil {
		return false, fmt.Errorf("unable to parse certificate expiration value of \"%s\": %w", notAfter, err)
	}

	return time.Now().After(t), nil
}

func lessLower(sa, sb string) bool {
	for {
		if len(sb) == 0 {
			return false
		}

		if len(sa) == 0 {
			return true
		}

		c, sizec := utf8.DecodeRuneInString(sa)
		d, sized := utf8.DecodeRuneInString(sb)

		lowerc := unicode.ToLower(c)
		lowerd := unicode.ToLower(d)

		if lowerc < lowerd {
			return true
		}

		if lowerc > lowerd {
			return false
		}

		sa = sa[sizec:]
		sb = sb[sized:]
	}
}

func reverse[S ~[]E, E any](s S) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
