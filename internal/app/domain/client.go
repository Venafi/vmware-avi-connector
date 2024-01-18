package domain

// Client represents a connection to a host
type Client struct {
	// Connection ...
	Connection *Connection
	// Session ...
	Session any
	// Tenant ...
	Tenant string
}
