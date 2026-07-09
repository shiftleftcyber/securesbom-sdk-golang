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

// Package main demonstrates how to call the SecureSBOM health-check endpoint.
//
// Usage:
//   go run main.go
//   go run main.go -base-url https://custom.api.example.com
//
// Environment variables:
//   SECURE_SBOM_API_KEY - Your API key (required)
//   SECURE_SBOM_BASE_URL - Custom API endpoint (optional)

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/shiftleftcyber/securesbom-sdk-golang/v2/pkg/securesbom"
)

func main() {
	apiKey := flag.String("api-key", "", "API key (or set SECURE_SBOM_API_KEY)")
	baseURL := flag.String("base-url", "", "API base URL (or set SECURE_SBOM_BASE_URL)")
	timeout := flag.Duration("timeout", 30*time.Second, "Request timeout")
	quiet := flag.Bool("quiet", false, "Suppress success output")
	help := flag.Bool("help", false, "Show usage information")
	flag.Parse()

	if *help {
		printUsage()
		return
	}

	client, err := createClient(*apiKey, *baseURL, *timeout)
	if err != nil {
		log.Fatalf("Error creating SDK client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := client.HealthCheck(ctx); err != nil {
		log.Fatalf("Health check failed: %v", err)
	}

	if !*quiet {
		fmt.Println("SecureSBOM API health check passed")
	}
}

func createClient(apiKey, baseURL string, timeout time.Duration) (securesbom.ClientInterface, error) {
	configBuilder := securesbom.NewConfigBuilder().
		WithTimeout(timeout).
		FromEnv()

	if apiKey != "" {
		configBuilder = configBuilder.WithAPIKey(apiKey)
	}
	if baseURL != "" {
		configBuilder = configBuilder.WithBaseURL(baseURL)
	}

	return configBuilder.BuildClient()
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `SecureSBOM SDK Health Check Example

Call the explicit SecureSBOM health-check endpoint.

USAGE:
  %s [options]

OPTIONS:
  -api-key string     API key (or set SECURE_SBOM_API_KEY)
  -base-url string    API base URL (or set SECURE_SBOM_BASE_URL)
  -timeout duration   Request timeout (default: 30s)
  -quiet              Suppress success output
  -help               Show this help message

EXAMPLES:
  # Check the default API endpoint
  %s

  # Check a custom API endpoint
  %s -base-url https://custom.api.example.com

ENVIRONMENT VARIABLES:
  SECURE_SBOM_API_KEY    Your SecureSBOM API key
  SECURE_SBOM_BASE_URL   Custom API endpoint URL

`, os.Args[0], os.Args[0], os.Args[0])
}
