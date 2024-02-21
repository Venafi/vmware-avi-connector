package domain

// Keystore represents the properties defined in the keystore definition in the manifest.json file
type Keystore struct {
	CertificateName string `json:"certificateName"`
	Tenant          string `json:"tenant"`
}
