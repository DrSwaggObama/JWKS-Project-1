# 🔐 JWKS Server

A lightweight JSON Web Key Set (JWKS) server implementation in Go that provides RSA key management and JWT token issuance for educational purposes.

## ✨ Features

- 🔑 **RSA Key Generation**: Automatically generates 2048-bit RSA key pairs with expiration timestamps
- 🌐 **JWKS Endpoint**: Serves public keys in standard JWKS format at `/.well-known/jwks.json`
- 🎫 **JWT Authentication**: Issues signed JWTs via `/auth` endpoint
- ⏰ **Key Expiration**: Only serves non-expired keys for enhanced security
- 🧪 **Testing Support**: Includes expired token generation for testing scenarios
- ✅ **Comprehensive Tests**: 80%+ test coverage with error simulation

## 🚀 Quick Start

### Prerequisites
- Go 1.19 or higher

### Installation & Running

1. **Clone the repository:**
   ```bash
   git clone https://github.com/DrSwaggObama/JWKS-Project-1.git
   cd JWKS-Project-1
   ```

2. **Install dependencies:**
   ```bash
   go mod download
   ```

3. **Run the server:**
   ```bash
   go run main.go
   ```

4. **Server starts on port 8080:**
   ```
   🔐 JWKS Server starting on :8080
   ```

## 📡 API Endpoints

### GET `/.well-known/jwks.json`
Returns public keys in JWKS format (only non-expired keys).

**Example Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "abc123",
      "use": "sig",
      "alg": "RS256",
      "n": "base64url-encoded-modulus",
      "e": "base64url-encoded-exponent"
    }
  ]
}
```

### POST `/auth`
Issues a signed JWT token.

**Example Response:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### POST `/auth?expired=true`
Issues a JWT signed with an expired key (for testing purposes).

## 🧪 Testing

### Run Test Suite
```bash
# Run all tests
go test

# Run with verbose output
go test -v

# Run with coverage report
go test -cover

# Generate HTML coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

### Manual Testing
```bash
# Test JWKS endpoint
curl http://localhost:8080/.well-known/jwks.json

# Test authentication
curl -X POST http://localhost:8080/auth

# Test expired token generation
curl -X POST "http://localhost:8080/auth?expired=true"

# Pretty print with jq (if installed)
curl -s http://localhost:8080/.well-known/jwks.json | jq .
```

## 📁 Project Structure

```
JWKS-Project-1/
├── main.go          # Server implementation (78 lines)
├── main_test.go     # Test suite (120 lines)
├── go.mod           # Go module definition
├── go.sum           # Dependency checksums
└── README.md        # This file
```

## 📦 Dependencies

- [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt) - JWT token handling
- [`github.com/google/uuid`](https://github.com/google/uuid) - UUID generation for key IDs

## 🔧 Implementation Details

- **Key Management**: Generates one valid key (24h expiry) and one expired key (for testing)
- **Security**: Only serves non-expired keys via JWKS endpoint
- **JWT Claims**: Includes standard claims (sub, exp, iat) with 1-hour token validity
- **Error Handling**: Proper HTTP status codes and error responses
- **Testing**: Comprehensive test coverage including error simulation

## 💻 Development

### Stopping the Server
- Press `Ctrl+C` in the terminal
- Or kill by port: `lsof -ti:8080 | xargs kill`

### Code Style
- Follows Go conventions
- Concise implementation (under 80 lines for server)
- Well-tested with dependency injection for testability

## ⚠️ Educational Purpose

> **Note**: This project is designed for learning JWKS/JWT concepts and should not be used in production without proper authentication, key rotation, and security hardening.

## 📄 License

This project is for educational use.
