package domain

type Connection struct {
	HostnameOrAddress string `json:"hostnameOrAddress"`
	Password          string `json:"password"`
	Port              int    `json:"port"`
	Username          string `json:"username"`
}
