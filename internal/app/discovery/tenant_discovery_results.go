package discovery

type tenantDiscoveryResults struct {
	Discovered int
	TenantMap  map[string][]*discoveredCertificateAndURL
}

func newTenantDiscoveryResults() *tenantDiscoveryResults {
	return &tenantDiscoveryResults{
		Discovered: 0,
		TenantMap:  map[string][]*discoveredCertificateAndURL{},
	}
}

func (tdr *tenantDiscoveryResults) append(tenant string, dcc []*discoveredCertificateAndURL) {
	existing, ok := tdr.TenantMap[tenant]
	if !ok {
		tdr.Discovered += len(dcc)
		tdr.TenantMap[tenant] = dcc
		return
	}

	for _, dc := range dcc {
		tdr.Discovered++
		existing = append(existing, dc)
	}

	tdr.TenantMap[tenant] = existing
}

func (tdr *tenantDiscoveryResults) collapse() []*DiscoveredCertificate {
	collapsed := make([]*DiscoveredCertificate, 0, tdr.Discovered)

	for _, results := range tdr.TenantMap {
		for _, dc := range results {
			collapsed = append(collapsed, dc.Result)
		}
	}

	return collapsed
}
