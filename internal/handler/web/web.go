// Package web contains the web server and registered routes
package web

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2"
)

// WebhookService ...
type WebhookService interface {
	HandleConfigureInstallationEndpoint(c echo.Context) error
	HandleDiscoverCertificates(c echo.Context) error
	HandleGetTargetConfiguration(c echo.Context) error
	HandleInstallCertificateBundle(c echo.Context) error
	HandleTestConnection(c echo.Context) error
}

// ConfigureHTTPServers creates an HTTP server with standard middleware and a system HTTP server with health and metrics endpoints
// returns the echo engine for serving API
func ConfigureHTTPServers(lifecycle fx.Lifecycle, shutdowner fx.Shutdowner) (*echo.Echo, error) {
	e := echo.New()

	lifecycle.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			go func() {
				if err := e.Start(":8080"); err != nil && err != http.ErrServerClosed {
					zap.L().Error("failed to start echo server", zap.Error(err))
					if err = shutdowner.Shutdown(); err != nil {
						zap.L().Error("fx shutdown error", zap.Error(err))
					}
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			return e.Shutdown(ctx)
		},
	})

	return e, nil
}

// RegisterHandlers will ...
func RegisterHandlers(e *echo.Echo, whService WebhookService) error {
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	g := e.Group("/v1")
	addPayloadEncryptionMiddleware(g)
	g.POST("/testconnection", whService.HandleTestConnection)
	g.POST("/gettargetconfiguration", whService.HandleGetTargetConfiguration)
	g.POST("/configureinstallationendpoint", whService.HandleConfigureInstallationEndpoint)
	g.POST("/installcertificatebundle", whService.HandleInstallCertificateBundle)
	g.POST("/discovercertificates", whService.HandleDiscoverCertificates)

	return nil
}

func addPayloadEncryptionMiddleware(g *echo.Group) {
	privateKeyPemData, err := os.ReadFile("/keys/payload-encryption-key.pem")
	if err != nil {
		zap.L().Error("payload encryption key not found or readable", zap.Error(err))
		return
	}
	p, _ := pem.Decode(privateKeyPemData)
	if p == nil {
		zap.L().Error("payload encryption key not in PEM format")
		return
	}
	pk, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		zap.L().Error("payload encryption key not properly encoded", zap.Error(err))
		return
	}
	zap.L().Info("adding payload encryption middleware")
	g.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				return err
			}
			object, err := jose.ParseEncrypted(string(body))
			if err != nil {
				return err
			}
			decrypted, err := object.Decrypt(pk)
			if err != nil {
				return err
			}
			req.Body = io.NopCloser(bytes.NewReader(decrypted))
			return next(c)
		}
	})
}
