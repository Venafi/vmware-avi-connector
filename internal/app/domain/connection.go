package domain

// Connection represents the properties defined in the connection definition in the manifest.json file.
type Connection struct {
	HostnameOrAddress string `json:"hostnameOrAddress"`
	Password          string `json:"password"`
	Port              int    `json:"port"`
	Username          string `json:"username"`
}
