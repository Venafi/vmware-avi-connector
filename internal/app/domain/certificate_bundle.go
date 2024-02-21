package domain

// CertificateBundle represents the properties defined in the mandatory certificate bundle definition in the manifest.json file
type CertificateBundle struct {
	Certificate      []byte   `json:"certificate"`
	PrivateKey       []byte   `json:"privateKey"`
	CertificateChain [][]byte `json:"certificateChain"`
}
