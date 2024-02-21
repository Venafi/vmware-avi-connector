package domain

// Client represents a connection to a VMware AVI host
type Client struct {
	// Connection contains the values supplied for the connetion properties defined in the manifest.json
	Connection *Connection
	// Session is the VMware AVI session
	Session any
	// Tenant is the name of the tenant
	Tenant string
}
