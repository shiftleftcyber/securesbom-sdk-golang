# SecureSBOM Go SDK

[![Go Version](https://img.shields.io/github/go-mod/go-version/shiftleftcyber/securesbom-sdk-golang)](https://go.dev/)
[![License](https://img.shields.io/github/license/shiftleftcyber/securesbom-sdk-golang)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/shiftleftcyber/securesbom-sdk-golang)](https://goreportcard.com/report/github.com/shiftleftcyber/securesbom-sdk-golang)
[![codecov](https://codecov.io/gh/shiftleftcyber/securesbom-sdk-golang/branch/main/graph/badge.svg)](https://codecov.io/gh/shiftleftcyber/securesbom-sdk-golang)
[![GoDoc](https://pkg.go.dev/badge/github.com/shiftleftcyber/securesbom-sdk-golang)](https://pkg.go.dev/github.com/shiftleftcyber/securesbom-sdk-golang)

A Go SDK for signing and verifying Software Bill of Materials (SBOM) documents using the ShiftLeftCyber SecureSBOM service.

## Features

- **Sign SBOMs**: Cryptographically sign SBOM documents for authenticity and integrity
- **Verify Signatures**: Validate signed SBOMs to ensure they haven't been tampered with
- **Key Management**: Generate, list, and retrieve signing keys
- **Production Ready**: Comprehensive error handling and testing

## Installation

```bash
go get github.com/shiftleftcyber/securesbom-go
```

## Quick Start

### API Key

Get your API key from [ShiftLeftCyber](https://shiftleftcyber.io/contactus).

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/shiftleftcyber/securesbom-go/pkg/securesbom"
)

func main() {
    // Create client
    client := securesbom.NewConfigBuilder().
        WithAPIKey("your-api-key").
        WithTimeout(30 * time.Second).
        FromEnv()
    
    if signBaseURL != "" {
		config = config.WithBaseURL(signBaseURL)
	}

    baseClient, err := config.BuildClient()
	if err != nil {
		return nil, err
	}

    ctx := context.Background()

    // Load SBOM
    sbom, err := securesbom.LoadSBOMFromFile("sbom.json")
    if err != nil {
        log.Fatal(err)
    }

    // Sign SBOM
    result, err := client.SignSBOM(ctx, "your-key-id", sbom.Data())
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("SBOM signed successfully\n")
}
```

## Usage Examples

### Signing an SBOM

```go
// Create client with retry logic
baseClient, _ := securesbom.NewConfigBuilder().
    WithAPIKey("your-api-key").
    FromEnv().
    BuildClient()

client := securesbom.WithRetryingClient(baseClient, securesbom.RetryConfig{
    MaxAttempts: 3,
    InitialWait: 1 * time.Second,
    MaxWait:     10 * time.Second,
    Multiplier:  2.0,
})

// Load and sign SBOM
sbom, _ := securesbom.LoadSBOMFromFile("sbom.json")
result, err := client.SignSBOM(ctx, "key-123", sbom.Data())
if err != nil {
    log.Fatal(err)
}

// Save signed SBOM
signedData, _ := json.Marshal(result)
os.WriteFile("signed-sbom.json", signedData, 0644)
```

### Verifying a Signed SBOM

```go
client, _ := securesbom.NewConfigBuilder().
    WithAPIKey("your-api-key").
    FromEnv().
    BuildClient()

// Load signed SBOM
signedSBOM, _ := securesbom.LoadSBOMFromFile("signed-sbom.json")

// Verify signature
result, err := client.VerifySBOM(ctx, "key-123", signedSBOM.Data())
if err != nil {
    log.Fatal(err)
}

if result.Valid {
    fmt.Println("✓ Signature is valid")
} else {
    fmt.Println("✗ Signature is invalid:", result.Message)
    os.Exit(1)
}
```

### Key Management

```go
client, _ := securesbom.NewConfigBuilder().
    WithAPIKey("your-api-key").
    BuildClient()

// List all keys
keys, err := client.ListKeys(ctx)
if err != nil {
    log.Fatal(err)
}

for _, key := range keys.Keys {
    fmt.Printf("Key: %s (created: %s)\n", key.ID, key.CreatedAt)
}

// Generate new key
newKey, err := client.GenerateKey(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("New key ID: %s\n", newKey.ID)

// Get public key
publicKey, err := client.GetPublicKey(ctx, newKey.ID)
if err != nil {
    log.Fatal(err)
}
fmt.Println(publicKey)
```

### Using Environment Variables

```go
// Set environment variables
// SECURE_SBOM_API_KEY=your-api-key

client, err := securesbom.NewConfigBuilder().
    FromEnv().
    BuildClient()
```

## Command Line Examples

The SDK includes example CLI applications demonstrating real-world usage.

### Install Examples

```bash
# Clone repository
git clone https://github.com/shiftleftcyber/securesbom-sdk-golang.git
cd securesbom-sdk-golang

# Build examples
make build-examples

# Or install to $GOPATH/bin
make install-examples
```

### Sign an SBOM

```bash
export SECURE_SBOM_API_KEY="your-api-key"

# Sign from file
./bin/sign -key-id my-key-123 -sbom sbom.json -output signed.json

# Sign from stdin
cat sbom.json | ./bin/sign -key-id my-key-123 > signed.json
```

### Verify a Signed SBOM

```bash
# Verify and show result
./bin/verify -key-id my-key-123 -sbom signed.json

# Verify with JSON output
./bin/verify -key-id my-key-123 -sbom signed.json -output json

# Use in scripts (check exit code)
if ./bin/verify -key-id my-key-123 -sbom signed.json -quiet; then
    echo "Valid signature"
else
    echo "Invalid signature"
    exit 1
fi
```

### Manage Keys

```bash
# List all keys
./bin/keymgmt list

# Generate new key
./bin/keymgmt generate

# Get public key
./bin/keymgmt public my-key-123 -output public.pem
```

## Configuration

### Configuration Builder

The SDK uses a builder pattern for flexible configuration:

```go
config := securesbom.NewConfigBuilder().
    WithAPIKey("api-key").           // Required
    WithTimeout(30 * time.Second).   // Optional (default: 30s)
    WithUserAgent("my-app/1.0").     // Optional
    FromEnv().                        // Load from environment
    Build()
```

### Retry Configuration

Add automatic retries with exponential backoff:

```go
retryConfig := securesbom.RetryConfig{
    MaxAttempts: 3,                    // Number of retry attempts
    InitialWait: 1 * time.Second,      // Initial wait time
    MaxWait:     10 * time.Second,     // Maximum wait time
    Multiplier:  2.0,                  // Backoff multiplier
}

retryingClient := securesbom.WithRetryingClient(baseClient, retryConfig)
```

### Environment Variables

- `SECURE_SBOM_API_KEY` - Your API key

## API Reference

### Client Methods

```go
type ClientInterface interface {
    // Health check
    HealthCheck(ctx context.Context) error
    
    // Key management
    ListKeys(ctx context.Context) (*KeyListResponse, error)
    GenerateKey(ctx context.Context) (*GeneratedKey, error)
    GetPublicKey(ctx context.Context, keyID string) (string, error)
    
    // SBOM operations
    SignSBOM(ctx context.Context, keyID string, sbom interface{}) (*SignResult, error)
    VerifySBOM(ctx context.Context, keyID string, signedSBOM interface{}) (*VerifyResult, error)
}
```

### SBOM Utilities

```go
// Load SBOM from various sources
sbom, err := securesbom.LoadSBOMFromFile("path/to/sbom.json")
sbom, err := securesbom.LoadSBOMFromReader(reader)

// Create SBOM from data
sbom := securesbom.NewSBOM(data)

// Write SBOM
err = sbom.WriteToFile("output.json")
err = sbom.WriteToWriter(writer)
str := sbom.String()
```

## Error Handling

The SDK provides structured error types:

```go
result, err := client.SignSBOM(ctx, keyID, sbom)
if err != nil {
    if apiErr, ok := err.(*securesbom.APIError); ok {
        fmt.Printf("API Error %d: %s\n", apiErr.StatusCode, apiErr.Message)
        if apiErr.Temporary() {
            // Retry logic
        }
    }
    return err
}
```

## Testing

```bash
# Run all tests
make test

# Run tests with coverage
make coverage

# Run only SDK tests (not examples)
make test-sdk

# Run short tests
make test-short
```

## Development

```bash
# Install development tools
make dev-setup

# Format code
make fmt

# Run linters
make lint

# Run all checks
make check

# Build examples
make build
```

## CI/CD

The project includes GitHub Actions workflows for:

- Pull Request validation (tests, lint, build)
- Main branch builds (artifacts published)
- Release automation (cross-platform binaries, documentation)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`make check`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.

## Support

- Documentation: [https://pkg.go.dev/github.com/shiftleftcyber/securesbom-sdk-golang](https://pkg.go.dev/github.com/shiftleftcyber/securesbom-sdk-golang)
- Issues: [GitHub Issues](https://github.com/shiftleftcyber/securesbom-sdk-golang/issues)
- Contact: [ShiftLeftCyber](https://shiftleftcyber.io/contactus)

## Acknowledgments

Built by [ShiftLeftCyber](https://shiftleftcyber.io) for securing software supply chains.
