// Package main implements the application main function.
package main

import (
	"github.com/venafi/vmware-avi-connector/cmd/vmware-avi-connector/app"
)

func main() {
	app.New().Run()
}
