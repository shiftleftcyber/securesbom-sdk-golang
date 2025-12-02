// Copyright 2025 ShiftLeftCyber Inc and Contributors
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main demonstrates how to use the SecureSBOM SDK to verify a signed SBOM document.
//
// This example shows:
// - Basic SDK setup and configuration
// - Loading a signed SBOM from file or stdin
// - Verifying signatures with proper error handling
// - Outputting verification results
//
// Usage:
//   go run main.go -key-id my-key-123 -sbom signed-sbom.json
//   cat signed-sbom.json | go run main.go -key-id my-key-123
//
// Environment variables:
//   SECURE_SBOM_API_KEY - Your API key (required)
//   SECURE_SBOM_BASE_URL - Custom API endpoint (optional)

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/shiftleftcyber/securesbom-sdk-golang/v2/pkg/securesbom"
)

func main() {
	// Command line flags
	var (
		keyID    = flag.String("key-id", "", "Key ID used to sign the SBOM (required)")
		sbomPath = flag.String("sbom", "", "Path to signed SBOM file (use '-' or omit for stdin)")
		signature = flag.String("signature", "", "signature to verify (used for SPDX)")
		apiKey   = flag.String("api-key", "", "API key (or set SECURE_SBOM_API_KEY)")
		baseURL  = flag.String("base-url", "", "API base URL (or set SECURE_SBOM_BASE_URL)")
		output   = flag.String("output", "text", "Output format: text, json")
		timeout  = flag.Duration("timeout", 30*time.Second, "Request timeout")
		retries  = flag.Int("retries", 3, "Number of retry attempts")
		quiet    = flag.Bool("quiet", false, "Suppress progress output (only show result)")
		help     = flag.Bool("help", false, "Show usage information")
	)
	flag.Parse()

	if *help {
		printUsage()
		return
	}

	// Validate required parameters
	if *keyID == "" {
		log.Fatal("Error: -key-id is required")
	}

	// Validate output format
	if *output != "text" && *output != "json" {
		log.Fatal("Error: -output must be 'text' or 'json'")
	}

	// Create SDK client with configuration
	client, err := createClient(*apiKey, *baseURL, *timeout, *retries)
	if err != nil {
		log.Fatalf("Error creating SDK client: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout+10*time.Second)
	defer cancel()

	// Load signed SBOM
	if !*quiet {
		fmt.Fprintf(os.Stderr, "Loading SBOM...\n")
	}
	sbom, err := loadSignedSBOM(*sbomPath)
	if err != nil {
		log.Fatalf("Error loading signed SBOM: %v", err)
	}

	// Verify API connectivity
	if !*quiet {
		fmt.Fprintf(os.Stderr, "Connecting to SecureSBOM API...\n")
	}
	if err := client.HealthCheck(ctx); err != nil {
		log.Fatalf("Error connecting to API: %v", err)
	}

	// Verify the SBOM signature
	if !*quiet {
		fmt.Fprintf(os.Stderr, "Verifying SBOM signature with key %s...\n", *keyID)
	}
	
	var result *securesbom.VerifyResultCMDResponse
	if signature == nil {
		// CycloneDX SBOM
		log.Print("Verifying CycloneDX SBOM")
		result, err = client.VerifySBOM(ctx, *keyID, sbom.Data())
		if err != nil {
			log.Fatalf("Error verifying SBOM: %v", err)
		}
	} else {
		log.Print("Verifying SPDX SBOM")
		result, err = client.VerifySPDXSBOM(ctx, *keyID, *signature, sbom.Data())
		if err != nil {
			log.Fatalf("Error verifying SBOM: %v", err)
		}
	}
	

	// Output verification result
	if err := outputVerificationResult(result, *output); err != nil {
		log.Fatalf("Error outputting verification result: %v", err)
	}

	// Exit with appropriate code
	if !result.Valid {
		os.Exit(1)
	}
}

// createClient builds and configures the SDK client
func createClient(apiKey, baseURL string, timeout time.Duration, retries int) (securesbom.ClientInterface, error) {
	// Build configuration using the SDK's builder pattern
	configBuilder := securesbom.NewConfigBuilder().
		WithTimeout(timeout).
		FromEnv() // Load from environment variables first

	// Override with command line parameters if provided
	if apiKey != "" {
		configBuilder = configBuilder.WithAPIKey(apiKey)
	}
	if baseURL != "" {
		configBuilder = configBuilder.WithBaseURL(baseURL)
	}

	// Create base client
	baseClient, err := configBuilder.BuildClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create base client: %w", err)
	}

	// Add retry logic if requested
	if retries > 0 {
		retryConfig := securesbom.RetryConfig{
			MaxAttempts: retries,
			InitialWait: 1 * time.Second,
			MaxWait:     10 * time.Second,
			Multiplier:  2.0,
		}
		return securesbom.WithRetryingClient(baseClient, retryConfig), nil
	}

	return baseClient, nil
}

// loadSignedSBOM loads a signed SBOM from file or stdin
func loadSignedSBOM(path string) (*securesbom.SBOM, error) {
	if path == "" || path == "-" {
		// Read from stdin
		return securesbom.LoadSBOMFromReader(os.Stdin)
	}

	// Read from file
	return securesbom.LoadSBOMFromFile(path)
}

// outputVerificationResult outputs the verification result in the specified format
func outputVerificationResult(result *securesbom.VerifyResultCMDResponse, format string) error {
	switch format {
	case "json":
		return outputVerificationJSON(result)
	case "text":
		return outputVerificationText(result)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// outputVerificationJSON outputs the result in JSON format
func outputVerificationJSON(result *securesbom.VerifyResultCMDResponse) error {
	output := map[string]interface{}{
		"valid":     result.Valid,
		"message":   result.Message,
		"timestamp": result.Timestamp.Format(time.RFC3339),
	}

	if result.Valid {
		output["status"] = "VALID"
	} else {
		output["status"] = "INVALID"
	}

	if result.KeyID != "" {
		output["key_id"] = result.KeyID
	}
	if result.Algorithm != "" {
		output["algorithm"] = result.Algorithm
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// outputVerificationText outputs the result in human-readable text format
func outputVerificationText(result *securesbom.VerifyResultCMDResponse) error {
	if result.Valid {
		fmt.Printf("✓ SBOM signature is VALID\n")
	} else {
		fmt.Printf("✗ SBOM signature is INVALID\n")
	}

	if result.Message != "" {
		fmt.Printf("Message:    %s\n", result.Message)
	}

	if result.KeyID != "" {
		fmt.Printf("Key ID:     %s\n", result.KeyID)
	}

	if result.Algorithm != "" {
		fmt.Printf("Algorithm:  %s\n", result.Algorithm)
	}

	if !result.Timestamp.IsZero() {
		fmt.Printf("Verified:   %s\n", result.Timestamp.Format(time.RFC3339))
	}

	return nil
}

// printUsage displays usage information
func printUsage() {
	fmt.Fprintf(os.Stderr, `SecureSBOM SDK Verify Example

Verify the authenticity and integrity of a signed SBOM document.

USAGE:
  %s -key-id KEY_ID [options]

REQUIRED:
  -key-id string    Key ID used to sign the SBOM

OPTIONS:
  -sbom string      Path to signed SBOM file (default: stdin)
  -output string    Output format: text, json (default: text)
  -api-key string   API key (or set SECURE_SBOM_API_KEY)
  -base-url string  API base URL (or set SECURE_SBOM_BASE_URL)
  -timeout duration Request timeout (default: 30s)
  -retries int      Number of retry attempts (default: 3)
  -quiet            Suppress progress output (only show result)
  -help             Show this help message

EXIT CODES:
  0  Signature is valid
  1  Signature is invalid or verification failed

EXAMPLES:
  # Verify signed SBOM from file
  %s -key-id my-key-123 -sbom signed-sbom.json

  # Verify from stdin with text output
  cat signed-sbom.json | %s -key-id my-key-123

  # Verify with JSON output for automation
  %s -key-id my-key-123 -sbom signed.json -output json

  # Verify with custom API endpoint
  %s -key-id my-key-123 -sbom signed.json -base-url https://custom.api.com

  # Verify in quiet mode (only show result)
  %s -key-id my-key-123 -sbom signed.json -quiet

  # Use in shell scripts (check exit code)
  if %s -key-id my-key-123 -sbom signed.json -quiet; then
    echo "Valid signature"
  else
    echo "Invalid signature"
  fi

ENVIRONMENT VARIABLES:
  SECURE_SBOM_API_KEY    Your SecureSBOM API key
  SECURE_SBOM_BASE_URL   Custom API endpoint URL

API KEY:
  You can obtain an API key from: https://shiftleftcyber.io/contactus

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
