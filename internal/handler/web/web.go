// Package web contains the web server and registered routes
package web

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2"
)

const payloadEncryptionKeyPath = "/keys/payload-encryption-key.pem"

// WebhookService interfaces for the connector operation functions
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

// RegisterHandlers adds the method handlers for the supported routes.
// It returns an error if payload encryption middleware cannot be configured,
// which causes fx to abort application start-up (fail-closed per CWE-636).
func RegisterHandlers(e *echo.Echo, whService WebhookService) error {
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	g := e.Group("/v1")

	// Fail-closed (CWE-636): propagate any key-loading error so that fx aborts
	// start-up. No route must ever be reachable without functioning decryption.
	if err := addPayloadEncryptionMiddleware(g); err != nil {
		return fmt.Errorf("failed to configure payload encryption middleware: %w", err)
	}

	g.POST("/testconnection", whService.HandleTestConnection)
	g.POST("/gettargetconfiguration", whService.HandleGetTargetConfiguration)
	g.POST("/configureinstallationendpoint", whService.HandleConfigureInstallationEndpoint)
	g.POST("/installcertificatebundle", whService.HandleInstallCertificateBundle)
	g.POST("/discovercertificates", whService.HandleDiscoverCertificates)

	return nil
}

// addPayloadEncryptionMiddleware loads the private key from the well-known path
// and registers JWE decryption middleware on the route group.
func addPayloadEncryptionMiddleware(g *echo.Group) error {
	return addPayloadEncryptionMiddlewareFromPath(g, payloadEncryptionKeyPath)
}

// addPayloadEncryptionMiddlewareFromPath registers JWE decryption middleware on
// the given route group using the RSA private key at keyPath.
//
// SECURITY: this function MUST return an error on any key-loading failure.
// Callers treat that error as fatal and must not serve the route group without
// the middleware in place (fail-closed per CWE-636: Not Failing Securely).
func addPayloadEncryptionMiddlewareFromPath(g *echo.Group, keyPath string) error {
	pk, err := loadRSAPrivateKey(keyPath)
	if err != nil {
		// Return the error — do NOT fall through and leave the group unprotected.
		return err
	}

	zap.L().Info("adding payload encryption middleware")
	g.Use(jweDecryptMiddleware(pk))
	return nil
}

// loadRSAPrivateKey reads and parses a PKCS#1 RSA private key from a PEM file.
func loadRSAPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	pemData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("payload encryption key not found or readable: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("payload encryption key not in PEM format")
	}

	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("payload encryption key not properly encoded: %w", err)
	}

	return pk, nil
}

// jweDecryptMiddleware returns an Echo middleware that decrypts JWE-encoded
// request bodies before passing them to the next handler.
// Any failure to parse or decrypt the token results in an HTTP error response,
// ensuring that JWE decryption failure is always fail-closed.
func jweDecryptMiddleware(pk *rsa.PrivateKey) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return err
			}

			object, err := jose.ParseEncrypted(string(body))
			if err != nil {
				// Body is not a valid JWE token — reject, never pass to handler.
				return echo.NewHTTPError(http.StatusBadRequest, "request body is not a valid JWE token")
			}

			decrypted, err := object.Decrypt(pk)
			if err != nil {
				// Decryption failure must be fail-closed: reject the request.
				return echo.NewHTTPError(http.StatusUnauthorized, "JWE decryption failed")
			}

			req.Body = io.NopCloser(bytes.NewReader(decrypted))
			return next(c)
		}
	}
}
