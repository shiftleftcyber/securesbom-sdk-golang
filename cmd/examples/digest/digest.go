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

// Package main demonstrates how to use the SecureSBOM SDK to sign a digest.
//
// This example shows:
// - Basic SDK setup and configuration
// - Signing a base64-encoded digest
// - Error handling and retries
// - Outputting the signature response
//
// Usage:
//   go run main.go -key-id my-key-123 -hash-algorithm sha256 -digest-b64 BASE64_DIGEST
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
	var (
		keyID         = flag.String("key-id", "", "Key ID to use for signing (required)")
		hashAlgorithm = flag.String("hash-algorithm", "", "Hash algorithm used to create the digest (required)")
		digestB64     = flag.String("digest", "", "Base64-encoded digest to sign (required)")
		outputPath    = flag.String("output", "", "Output file path (use '-' or omit for stdout)")
		apiKey        = flag.String("api-key", "", "API key (or set SECURE_SBOM_API_KEY)")
		baseURL       = flag.String("base-url", "", "API base URL (or set SECURE_SBOM_BASE_URL)")
		timeout       = flag.Duration("timeout", 30*time.Second, "Request timeout")
		retries       = flag.Int("retries", 3, "Number of retry attempts")
		quiet         = flag.Bool("quiet", false, "Suppress progress output")
		pretty        = flag.Bool("pretty", false, "Pretty-print JSON output")
		help          = flag.Bool("help", false, "Show usage information")
	)
	flag.Parse()

	if *help {
		printUsage()
		return
	}

	if *keyID == "" {
		log.Fatal("Error: -key-id is required")
	}
	if *hashAlgorithm == "" {
		log.Fatal("Error: -hash-algorithm is required")
	}
	if *digestB64 == "" {
		log.Fatal("Error: -digest is required")
	}

	client, err := createClient(*apiKey, *baseURL, *timeout, *retries)
	if err != nil {
		log.Fatalf("Error creating SDK client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+10*time.Second)
	defer cancel()

	if !*quiet {
		fmt.Fprintf(os.Stderr, "Connecting to SecureSBOM API...\n")
	}
	if err := client.HealthCheck(ctx); err != nil {
		log.Fatalf("Error connecting to API: %v", err)
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "Signing digest with key %s...\n", *keyID)
	}

	result, err := client.SignDigest(ctx, securesbom.SignDigestRequest{
		DigestB64:     *digestB64,
		HashAlgorithm: *hashAlgorithm,
		KeyID:         *keyID,
	})
	if err != nil {
		log.Fatalf("Error signing digest: %v", err)
	}

	if err := outputSignedDigest(result, *outputPath, *pretty); err != nil {
		log.Fatalf("Error outputting digest signature: %v", err)
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "✓ Digest successfully signed\n")
		if *outputPath != "" && *outputPath != "-" {
			fmt.Fprintf(os.Stderr, "  Output written to: %s\n", *outputPath)
		} else {
			fmt.Fprintf(os.Stderr, "  Output written to stdout\n")
		}
	}
}

func createClient(apiKey, baseURL string, timeout time.Duration, retries int) (securesbom.ClientInterface, error) {
	configBuilder := securesbom.NewConfigBuilder().
		WithTimeout(timeout).
		FromEnv()

	if apiKey != "" {
		configBuilder = configBuilder.WithAPIKey(apiKey)
	}
	if baseURL != "" {
		configBuilder = configBuilder.WithBaseURL(baseURL)
	}

	baseClient, err := configBuilder.BuildClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create base client: %w", err)
	}

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

func outputSignedDigest(result *securesbom.SignDigestResponse, outputPath string, pretty bool) error {
	var (
		jsonData []byte
		err      error
	)

	if pretty {
		jsonData, err = json.MarshalIndent(result, "", "  ")
	} else {
		jsonData, err = json.Marshal(result)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal digest signature response: %w", err)
	}

	if outputPath == "" || outputPath == "-" {
		fmt.Print(string(jsonData))
		fmt.Println()
		return nil
	}

	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", outputPath, err)
	}

	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `SecureSBOM SDK Digest Sign Example

Sign a base64-encoded digest using the SecureSBOM service.

USAGE:
  %s -key-id KEY_ID -hash-algorithm HASH -digest-b64 DIGEST [options]

REQUIRED:
  -key-id string            Key ID to use for signing
  -hash-algorithm string    Hash algorithm used to create the digest
  -digest-b64 string        Base64-encoded digest to sign

OPTIONS:
  -pretty bool      Pretty-print the response JSON
  -output string    Output file path (default: stdout)
  -api-key string   API key (or set SECURE_SBOM_API_KEY)
  -base-url string  API base URL (or set SECURE_SBOM_BASE_URL)
  -timeout duration Request timeout (default: 30s)
  -retries int      Number of retry attempts (default: 3)
  -quiet            Suppress progress output
  -help             Show this help message

EXAMPLES:
  # Sign a SHA-256 digest
  %s -key-id my-key-123 -hash-algorithm sha256 -digest Zm9vYmFy

  # Write the response to a file
  %s -key-id my-key-123 -hash-algorithm sha256 -digest Zm9vYmFy -output signed-digest.json

  # Sign with a custom API endpoint
  %s -key-id my-key-123 -hash-algorithm sha256 -digest Zm9vYmFy -base-url https://custom.api.com

ENVIRONMENT VARIABLES:
  SECURE_SBOM_API_KEY    Your SecureSBOM API key
  SECURE_SBOM_BASE_URL   Custom API endpoint URL

API KEY:
  You can obtain an API key from: https://shiftleftcyber.io/contactus

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}
