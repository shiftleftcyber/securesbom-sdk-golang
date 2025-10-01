// Package main demonstrates how to use the SecureSBOM SDK for key management operations.
//
// This example shows:
// - Listing available signing keys
// - Generating new signing keys
// - Retrieving public keys
//
// Usage:
//   go run main.go list
//   go run main.go generate
//   go run main.go public <key-id>
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
	"text/tabwriter"
	"time"

	"github.com/shiftleftcyber/securesbom-sdk-golang/pkg/securesbom"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "list":
		runListCommand(os.Args[2:])
	case "generate":
		runGenerateCommand(os.Args[2:])
	case "public":
		runPublicCommand(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

// runListCommand lists all available keys
func runListCommand(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	apiKey := fs.String("api-key", "", "API key (or set SECURE_SBOM_API_KEY)")
	baseURL := fs.String("base-url", "", "API base URL (or set SECURE_SBOM_BASE_URL)")
	output := fs.String("output", "table", "Output format: table, json")
	timeout := fs.Duration("timeout", 30*time.Second, "Request timeout")
	quiet := fs.Bool("quiet", false, "Suppress progress output")
	fs.Parse(args)

	// Validate output format
	if *output != "table" && *output != "json" {
		log.Fatal("Error: output must be 'table' or 'json'")
	}

	// Create client
	client, err := createClient(*apiKey, *baseURL, *timeout)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// List keys
	if !*quiet {
		fmt.Fprintf(os.Stderr, "Retrieving keys from SecureSBOM...\n")
	}

	result, err := client.ListKeys(ctx)
	if err != nil {
		log.Fatalf("Error listing keys: %v", err)
	}

	// Output results
	if *output == "json" {
		outputJSON(result)
	} else {
		outputKeysTable(result)
	}
}

// runGenerateCommand generates a new signing key
func runGenerateCommand(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	apiKey := fs.String("api-key", "", "API key (or set SECURE_SBOM_API_KEY)")
	baseURL := fs.String("base-url", "", "API base URL (or set SECURE_SBOM_BASE_URL)")
	output := fs.String("output", "table", "Output format: table, json")
	savePublic := fs.String("save-public", "", "Save public key to file")
	timeout := fs.Duration("timeout", 30*time.Second, "Request timeout")
	quiet := fs.Bool("quiet", false, "Suppress progress output")
	fs.Parse(args)

	// Validate output format
	if *output != "table" && *output != "json" {
		log.Fatal("Error: output must be 'table' or 'json'")
	}

	// Create client
	client, err := createClient(*apiKey, *baseURL, *timeout)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Generate key
	if !*quiet {
		fmt.Fprintf(os.Stderr, "Generating new signing key...\n")
	}

	key, err := client.GenerateKey(ctx)
	if err != nil {
		log.Fatalf("Error generating key: %v", err)
	}

	// Save public key if requested
	if *savePublic != "" {
		if err := os.WriteFile(*savePublic, []byte(key.PublicKey), 0644); err != nil {
			log.Fatalf("Error saving public key: %v", err)
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "Public key saved to: %s\n", *savePublic)
		}
	}

	// Output results
	if *output == "json" {
		outputJSON(key)
	} else {
		outputGeneratedKeyTable(key)
	}
}

// runPublicCommand retrieves the public key for a specific key ID
func runPublicCommand(args []string) {
	fs := flag.NewFlagSet("public", flag.ExitOnError)
	apiKey := fs.String("api-key", "", "API key (or set SECURE_SBOM_API_KEY)")
	baseURL := fs.String("base-url", "", "API base URL (or set SECURE_SBOM_BASE_URL)")
	outputFile := fs.String("output", "", "Output file (default: stdout)")
	timeout := fs.Duration("timeout", 30*time.Second, "Request timeout")
	quiet := fs.Bool("quiet", false, "Suppress progress output")
	fs.Parse(args)

	if fs.NArg() < 1 {
		log.Fatal("Error: key-id is required\n\nUsage: keymgmt public <key-id> [options]")
	}

	keyID := fs.Arg(0)

	// Create client
	client, err := createClient(*apiKey, *baseURL, *timeout)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Get public key
	if !*quiet {
		fmt.Fprintf(os.Stderr, "Retrieving public key for %s...\n", keyID)
	}

	publicKey, err := client.GetPublicKey(ctx, keyID)
	if err != nil {
		log.Fatalf("Error getting public key: %v", err)
	}

	// Output public key
	if *outputFile == "" {
		fmt.Print(publicKey)
	} else {
		if err := os.WriteFile(*outputFile, []byte(publicKey), 0644); err != nil {
			log.Fatalf("Error writing public key to file: %v", err)
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "Public key saved to: %s\n", *outputFile)
		}
	}
}

// createClient builds and configures the SDK client
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

// outputKeysTable displays keys in a formatted table
func outputKeysTable(result *securesbom.KeyListResponse) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "KEY ID\tCREATED\tALGORITHM\n")
	fmt.Fprintf(w, "------\t-------\t---------\n")

	for _, key := range result.Keys {
		createdAt := key.CreatedAt.Format("2006-01-02 15:04")
		algorithm := key.Algorithm
		if algorithm == "" {
			algorithm = "default"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", key.ID, createdAt, algorithm)
	}

	if len(result.Keys) == 0 {
		fmt.Fprintf(w, "No keys found\t\t\n")
	}
}

// outputGeneratedKeyTable displays a newly generated key in a formatted way
func outputGeneratedKeyTable(key *securesbom.GenerateKeyCMDResponse) {
	fmt.Printf("✓ New key generated successfully\n\n")
	fmt.Printf("Key ID:     %s\n", key.ID)
	fmt.Printf("Created:    %s\n", key.CreatedAt.Format(time.RFC3339))
	if key.Algorithm != "" {
		fmt.Printf("Algorithm:  %s\n", key.Algorithm)
	}

	if key.PublicKey != "" {
		fmt.Printf("\nPublic Key:\n")
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Print(key.PublicKey)
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	}

	fmt.Printf("\nYou can now use this key ID for signing:\n")
	fmt.Printf("  sign -key-id %s -sbom your-sbom.json\n", key.ID)
}

// outputJSON outputs data in JSON format
func outputJSON(data interface{}) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

// printUsage displays usage information
func printUsage() {
	fmt.Fprintf(os.Stderr, `SecureSBOM SDK Key Management Example

Manage cryptographic keys for signing and verifying SBOMs.

USAGE:
  keymgmt <command> [options]

COMMANDS:
  list                List all available signing keys
  generate            Generate a new signing key
  public <key-id>     Get the public key for a specific key ID
  help                Show this help message

LIST OPTIONS:
  -output string      Output format: table, json (default: table)
  -api-key string     API key (or set SECURE_SBOM_API_KEY)
  -base-url string    API base URL (or set SECURE_SBOM_BASE_URL)
  -timeout duration   Request timeout (default: 30s)
  -quiet              Suppress progress output

GENERATE OPTIONS:
  -output string      Output format: table, json (default: table)
  -save-public string Save public key to file
  -api-key string     API key (or set SECURE_SBOM_API_KEY)
  -base-url string    API base URL (or set SECURE_SBOM_BASE_URL)
  -timeout duration   Request timeout (default: 30s)
  -quiet              Suppress progress output

PUBLIC OPTIONS:
  -output string      Output file path (default: stdout)
  -api-key string     API key (or set SECURE_SBOM_API_KEY)
  -base-url string    API base URL (or set SECURE_SBOM_BASE_URL)
  -timeout duration   Request timeout (default: 30s)
  -quiet              Suppress progress output

EXAMPLES:
  # List all keys
  keymgmt list

  # List keys in JSON format
  keymgmt list -output json

  # Generate a new key
  keymgmt generate

  # Generate a new key and save public key to file
  keymgmt generate -save-public public.pem

  # Get public key for a specific key
  keymgmt public my-key-123

  # Save public key to file
  keymgmt public my-key-123 -output public.pem

ENVIRONMENT VARIABLES:
  SECURE_SBOM_API_KEY    Your SecureSBOM API key
  SECURE_SBOM_BASE_URL   Custom API endpoint URL

API KEY:
  You can obtain an API key from: https://shiftleftcyber.io/contactus

`)
}
