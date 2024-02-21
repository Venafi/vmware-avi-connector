// Package domain contains shared definitions.
package domain

// Binding represents the properties defined in the binding definition in the manifest.json file
type Binding struct {
	VirtualServiceName string `json:"virtualServiceName"`
}
