package domain

// CertificateBundle represents ...
type CertificateBundle struct {
	Certificate      []byte   `json:"certificate"`
	PrivateKey       []byte   `json:"privateKey"`
	CertificateChain [][]byte `json:"certificateChain"`
}
