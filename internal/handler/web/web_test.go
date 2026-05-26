package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// writeRSAKeyPEMFile generates a fresh RSA-2048 key, writes it to a temp file
// in PKCS#1 PEM format, and returns the file path together with the private key.
func writeRSAKeyPEMFile(t *testing.T) (keyPath string, pk *rsa.PrivateKey) {
	t.Helper()
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	}
	dir := t.TempDir()
	keyPath = filepath.Join(dir, "payload-encryption-key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600))
	return keyPath, pk
}

// encryptJWE encrypts plaintext with the given RSA public key and returns a
// compact-serialised JWE string.
func encryptJWE(t *testing.T, pub *rsa.PublicKey, plaintext []byte) string {
	t.Helper()
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP, Key: pub},
		nil,
	)
	require.NoError(t, err)
	obj, err := enc.Encrypt(plaintext)
	require.NoError(t, err)
	s, err := obj.CompactSerialize()
	require.NoError(t, err)
	return s
}

// newEchoWithMiddleware returns an *echo.Echo whose /v1 group has JWE
// decryption middleware loaded from keyPath, and a POST /v1/test handler that
// returns the (decrypted) request body as the response body.
func newEchoWithMiddleware(t *testing.T, keyPath string) *echo.Echo {
	t.Helper()
	e := echo.New()
	g := e.Group("/v1")
	require.NoError(t, addPayloadEncryptionMiddlewareFromPath(g, keyPath))
	g.POST("/test", func(c echo.Context) error {
		b, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return err
		}
		return c.String(http.StatusOK, string(b))
	})
	return e
}

// ---------------------------------------------------------------------------
// Fail-closed tests (CWE-636)
// ---------------------------------------------------------------------------

// TestAddPayloadEncryptionMiddleware_MissingKey asserts that a missing key file
// causes an error rather than silently leaving the route group unprotected.
func TestAddPayloadEncryptionMiddleware_MissingKey(t *testing.T) {
	g := echo.New().Group("/v1")
	err := addPayloadEncryptionMiddlewareFromPath(g, "/nonexistent/path/key.pem")
	require.Error(t, err,
		"missing key file must return an error (fail-closed, CWE-636)")
}

// TestAddPayloadEncryptionMiddleware_InvalidPEM asserts fail-closed when the
// key file exists but its content is not valid PEM.
func TestAddPayloadEncryptionMiddleware_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(path, []byte("this is not pem data"), 0600))

	g := echo.New().Group("/v1")
	err := addPayloadEncryptionMiddlewareFromPath(g, path)
	require.Error(t, err,
		"invalid PEM content must return an error (fail-closed, CWE-636)")
}

// TestAddPayloadEncryptionMiddleware_InvalidKey asserts fail-closed when the
// PEM frame is valid but the contained bytes are not a parseable RSA key.
func TestAddPayloadEncryptionMiddleware_InvalidKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("not-a-real-key")}
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0600))

	g := echo.New().Group("/v1")
	err := addPayloadEncryptionMiddlewareFromPath(g, path)
	require.Error(t, err,
		"malformed RSA key bytes must return an error (fail-closed, CWE-636)")
}

// TestRegisterHandlers_FailsWithoutKey verifies that RegisterHandlers returns a
// non-nil error when the well-known key file is absent, so that fx aborts
// application start-up instead of serving unprotected routes.
func TestRegisterHandlers_FailsWithoutKey(t *testing.T) {
	e := echo.New()
	err := RegisterHandlers(e, nil)
	require.Error(t, err,
		"RegisterHandlers must fail when encryption key is missing (fail-closed, CWE-636)")
}

// ---------------------------------------------------------------------------
// Runtime middleware tests
// ---------------------------------------------------------------------------

// TestMiddleware_RejectsPlaintext verifies that a plain-text (non-JWE) body is
// rejected with HTTP 400 and never forwarded to the handler.
func TestMiddleware_RejectsPlaintext(t *testing.T) {
	keyPath, _ := writeRSAKeyPEMFile(t)
	e := newEchoWithMiddleware(t, keyPath)

	req := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader("not-a-jwe-token"))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"plain-text body must be rejected with 400 (fail-closed)")
}

// TestMiddleware_RejectsWrongKey verifies that a structurally valid JWE
// encrypted with a *different* key is rejected with HTTP 401.
func TestMiddleware_RejectsWrongKey(t *testing.T) {
	serverKeyPath, _ := writeRSAKeyPEMFile(t)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	token := encryptJWE(t, &otherKey.PublicKey, []byte(`{"field":"value"}`))

	e := newEchoWithMiddleware(t, serverKeyPath)

	req := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(token))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"JWE encrypted with the wrong key must be rejected with 401 (fail-closed)")
}

// TestMiddleware_AcceptsValidJWE verifies the happy path: a request correctly
// encrypted with the server's public key is decrypted and forwarded to the handler.
func TestMiddleware_AcceptsValidJWE(t *testing.T) {
	keyPath, pk := writeRSAKeyPEMFile(t)
	payload := []byte(`{"hello":"world"}`)
	token := encryptJWE(t, &pk.PublicKey, payload)

	e := newEchoWithMiddleware(t, keyPath)

	req := httptest.NewRequest(http.MethodPost, "/v1/test", strings.NewReader(token))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "valid JWE must be accepted")
	assert.Equal(t, string(payload), rec.Body.String(),
		"handler must receive the decrypted plaintext payload")
}
