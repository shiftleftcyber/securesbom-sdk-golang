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

// Package main demonstrates how to use the SecureSBOM SDK to sign an SBOM document.
//
// This example shows:
// - Basic SDK setup and configuration
// - Loading an SBOM from file or stdin
// - Signing with error handling and retries
// - Outputting the signed SBOM
//
// Usage:
//   go run main.go -key-id my-key-123 -sbom sbom.json -output signed-sbom.json
//   cat sbom.json | go run main.go -key-id my-key-123 > signed-sbom.json
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

	"github.com/shiftleftcyber/securesbom-sdk-golang/pkg/securesbom"
)

func main() {
	// Command line flags
	var (
		keyID      = flag.String("key-id", "", "Key ID to use for signing (required)")
		sbomPath   = flag.String("sbom", "", "Path to SBOM file (use '-' or omit for stdin)")
		outputPath = flag.String("output", "", "Output file path (use '-' or omit for stdout)")
		apiKey     = flag.String("api-key", "", "API key (or set SECURE_SBOM_API_KEY)")
		baseURL    = flag.String("base-url", "", "API base URL (or set SECURE_SBOM_BASE_URL)")
		timeout    = flag.Duration("timeout", 30*time.Second, "Request timeout")
		retries    = flag.Int("retries", 3, "Number of retry attempts")
		quiet      = flag.Bool("quiet", false, "Suppress progress output")
		help       = flag.Bool("help", false, "Show usage information")
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

	// Create SDK client with configuration
	client, err := createClient(*apiKey, *baseURL, *timeout, *retries)
	if err != nil {
		log.Fatalf("Error creating SDK client: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout+10*time.Second)
	defer cancel()

	// Load SBOM
	if !*quiet {
		fmt.Fprintf(os.Stderr, "Loading SBOM...\n")
	}
	sbom, err := loadSBOM(*sbomPath)
	if err != nil {
		log.Fatalf("Error loading SBOM: %v", err)
	}

	// Verify API connectivity
	if !*quiet {
		fmt.Fprintf(os.Stderr, "Connecting to SecureSBOM API...\n")
	}
	if err := client.HealthCheck(ctx); err != nil {
		log.Fatalf("Error connecting to API: %v", err)
	}

	// Sign the SBOM
	if !*quiet {
		fmt.Fprintf(os.Stderr, "Signing SBOM with key %s...\n", *keyID)
	}
	result, err := client.SignSBOM(ctx, *keyID, sbom.Data())
	if err != nil {
		log.Fatalf("Error signing SBOM: %v", err)
	}

	// Output the signed SBOM
	if err := outputSignedSBOM(result, *outputPath); err != nil {
		log.Fatalf("Error outputting signed SBOM: %v", err)
	}

	// Success message
	if !*quiet {
		fmt.Fprintf(os.Stderr, "✓ SBOM successfully signed\n")
		if *outputPath != "" && *outputPath != "-" {
			fmt.Fprintf(os.Stderr, "  Output written to: %s\n", *outputPath)
		} else {
			fmt.Fprintf(os.Stderr, "  Output written to stdout\n")
		}
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

// loadSBOM loads an SBOM from file or stdin
func loadSBOM(path string) (*securesbom.SBOM, error) {
	if path == "" || path == "-" {
		// Read from stdin
		return securesbom.LoadSBOMFromReader(os.Stdin)
	}

	// Read from file
	return securesbom.LoadSBOMFromFile(path)
}

// outputSignedSBOM writes the signed SBOM to the specified output
func outputSignedSBOM(result *securesbom.SignResultAPIResponse, outputPath string) error {
	// Pretty-print the JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal signed SBOM: %w", err)
	}

	if outputPath == "" || outputPath == "-" {
		// Write to stdout
		fmt.Print(string(jsonData))
		fmt.Println() // Add newline for better terminal output
		return nil
	}

	// Write to file
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", outputPath, err)
	}

	return nil
}

// printUsage displays usage information
func printUsage() {
	fmt.Fprintf(os.Stderr, `SecureSBOM SDK Sign Example

Sign an SBOM document using the SecureSBOM service.

USAGE:
  %s -key-id KEY_ID [options]

REQUIRED:
  -key-id string    Key ID to use for signing

OPTIONS:
  -sbom string      Path to SBOM file (default: stdin)
  -output string    Output file path (default: stdout)
  -api-key string   API key (or set SECURE_SBOM_API_KEY)
  -base-url string  API base URL (or set SECURE_SBOM_BASE_URL)
  -timeout duration Request timeout (default: 30s)
  -retries int      Number of retry attempts (default: 3)
  -quiet            Suppress progress output
  -help             Show this help message

EXAMPLES:
  # Sign SBOM from file
  %s -key-id my-key-123 -sbom sbom.json -output signed.json

  # Sign from stdin, output to stdout
  cat sbom.json | %s -key-id my-key-123 > signed.json

  # Sign with custom API endpoint
  %s -key-id my-key-123 -sbom sbom.json -base-url https://custom.api.com

  # Sign with retry disabled
  %s -key-id my-key-123 -sbom sbom.json -retries 0

ENVIRONMENT VARIABLES:
  SECURE_SBOM_API_KEY    Your SecureSBOM API key
  SECURE_SBOM_BASE_URL   Custom API endpoint URL

API KEY:
  You can obtain an API key from: https://shiftleftcyber.io/contactus

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
