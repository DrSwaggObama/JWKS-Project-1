package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Test key generation and JWK conversion
func TestGenerateKeyPairAndToJWK(t *testing.T) {
	kp, err := generateKeyPair(time.Now().Add(time.Hour))
	if err != nil || kp.PrivateKey == nil || kp.PublicKey == nil {
		t.Fatalf("Key generation failed: %v", err)
	}
	jwk := kp.toJWK()
	if jwk.Kty != "RSA" || jwk.Kid != kp.Kid || jwk.N == "" || jwk.E == "" {
		t.Errorf("Invalid JWK: %+v", jwk)
	}
}

// Test JWKS endpoint with valid key
func TestJWKSHandler_ValidKey(t *testing.T) {
	validKey, _ = generateKeyPair(time.Now().Add(time.Hour))
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var jwks JWKS
	json.Unmarshal(w.Body.Bytes(), &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != validKey.Kid {
		t.Errorf("Expected 1 key with Kid %s", validKey.Kid)
	}
}

// Test JWKS endpoint with expired key
func TestJWKSHandler_ExpiredKey(t *testing.T) {
	validKey, _ = generateKeyPair(time.Now().Add(-time.Hour))
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)

	var jwks JWKS
	json.Unmarshal(w.Body.Bytes(), &jwks)
	if len(jwks.Keys) != 0 {
		t.Errorf("Expected 0 keys for expired key, got %d", len(jwks.Keys))
	}
}

// Test JWKS wrong method
func TestJWKSHandler_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	jwksHandler(w, req)
	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// Test auth endpoint with valid token
func TestAuthHandler_Valid(t *testing.T) {
	validKey, _ = generateKeyPair(time.Now().Add(time.Hour))
	req := httptest.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if token := resp["token"]; token == "" || len(strings.Split(token, ".")) != 3 {
		t.Error("Invalid JWT token")
	}
}

// Test auth endpoint with expired token
func TestAuthHandler_Expired(t *testing.T) {
	expiredKey, _ = generateKeyPair(time.Now().Add(-time.Hour))
	req := httptest.NewRequest("POST", "/auth?expired=true", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["token"] == "" {
		t.Error("Expected token in response")
	}
}

// Test auth endpoint with no keys
func TestAuthHandler_NoKeys(t *testing.T) {
	validKey, expiredKey = nil, nil
	req := httptest.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Code != 500 {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// Test auth wrong method
func TestAuthHandler_WrongMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Code != 405 {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

// Test signing failure simulation
func TestAuthHandler_SignFailure(t *testing.T) {
	validKey, _ = generateKeyPair(time.Now().Add(time.Hour))
	originalSign := signFunc
	signFunc = func(*rsa.PrivateKey, jwt.SigningMethod, *jwt.Token) (string, error) {
		return "", errors.New("sign failure")
	}
	defer func() { signFunc = originalSign }()

	req := httptest.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()
	authHandler(w, req)
	if w.Code != 500 {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

// Test key generation failure
func TestInitKeysFailure(t *testing.T) {
	original := generateKeyPairFunc
	generateKeyPairFunc = func(time.Time) (*KeyPair, error) {
		return nil, errors.New("generation failure")
	}
	defer func() { generateKeyPairFunc = original }()

	if err := initKeys(); err == nil {
		t.Error("Expected error from initKeys")
	}
}