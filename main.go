package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)
// Data structures for RSA key pair management
type KeyPair struct {
	Kid        string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	ExpiresAt  time.Time
}

// JSON Web Key format for JWKS response
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JSON Web key set containing multiple JWKSs
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Global key storage and test injection points
var (
	validKey   *KeyPair
	expiredKey *KeyPair
	// Test injection points
	generateKeyPairFunc = generateKeyPair
	signFunc            = func(k *rsa.PrivateKey, _ jwt.SigningMethod, token *jwt.Token) (string, error) {
		return token.SignedString(k)
	}
)

// Key generation utilities
func generateKeyPair(expiresAt time.Time) (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &KeyPair{uuid.New().String(), key, &key.PublicKey, expiresAt}, nil
}

func (kp *KeyPair) toJWK() JWK {
	n := base64.RawURLEncoding.EncodeToString(kp.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(kp.PublicKey.E)).Bytes())
	return JWK{"RSA", kp.Kid, "sig", "RS256", n, e}
}

// HTTP handlers for JWKS and authentication endpoints 
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	var keys []JWK
	if validKey != nil && time.Now().Before(validKey.ExpiresAt) {
		keys = append(keys, validKey.toJWK())
	}
	json.NewEncoder(w).Encode(JWKS{keys})
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	
	var keyToUse *KeyPair
	var exp int64
	if r.URL.Query().Get("expired") != "" && expiredKey != nil {
		keyToUse, exp = expiredKey, expiredKey.ExpiresAt.Unix()
	} else if validKey != nil {
		keyToUse, exp = validKey, time.Now().Add(time.Hour).Unix()
	} else {
		http.Error(w, "No keys available", 500)
		return
	}

	claims := jwt.MapClaims{"sub": "user123", "exp": exp, "iat": time.Now().Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyToUse.Kid
	
	tokenString, err := signFunc(keyToUse.PrivateKey, jwt.SigningMethodRS256, token)
	if err != nil {
		http.Error(w, "Failed to sign token", 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// Server initialization and startup 
func initKeys() error {
	var err error
	if validKey, err = generateKeyPairFunc(time.Now().Add(24 * time.Hour)); err != nil {
		return err
	}
	expiredKey, err = generateKeyPairFunc(time.Now().Add(-time.Hour))
	return err
}

func main() {
	if err := initKeys(); err != nil {
		log.Fatal("Failed to generate keys:", err)
	}
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)
	fmt.Println("🔐 JWKS Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
