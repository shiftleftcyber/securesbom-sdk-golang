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

// Package securesbom provides a Go SDK for interacting with the SecureSBOM API by ShiftLeftCyber.
//
// This SDK is designed to be framework-agnostic and can be used in CLI tools,
// web applications, or any other Go application that needs to cryptographically sign and verify SBOMs.
//
// Basic usage:
//
//	client := securesbom.NewClient(&securesbom.Config{
//		BaseURL: "https://your-api.googleapis.com",
//		APIKey:  "your-api-key",
//	})
//
//	// Sign an SBOM
//	result, err := client.SignSBOM(ctx, "key-id", sbomData)
//
//	// Verify an SBOM
//	result, err := client.VerifySBOM(ctx, "key-id", signedSBOM)

package securesbom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTimeout = 30 * time.Second
	UserAgent      = "secure-sbom-sdk-go/2.0"
	KeyBackendFile = "file"
	KeyBackendKMS  = "gcp-kms"
)

type Client struct {
	config     *Config
	httpClient HTTPClient
}

type ClientInterface interface {
	HealthCheck(ctx context.Context) error
	ListKeys(ctx context.Context) (*KeyListResponse, error)
	GenerateKey(ctx context.Context) (*GenerateKeyCMDResponse, error)
	GenerateKeyWithBackend(ctx context.Context, backend string) (*GenerateKeyCMDResponse, error)
	GetPublicKey(ctx context.Context, keyID string) (string, error)
	SignSBOM(ctx context.Context, keyID string, sbom interface{}) (*SignResultAPIResponseV2, error)
	SignSBOMWithOptions(ctx context.Context, keyID string, sbom interface{}, opts SignOptions) (*SignResultAPIResponseV2, error)
	SignDigest(ctx context.Context, req SignDigestRequest) (*SignDigestResponse, error)
	VerifySBOM(ctx context.Context, req VerifyCMDRequest) (*VerifyResultCMDResponse, error)
}

func (e *APIError) Error() string {
	prefix := "secure-sbom API error"
	if e.Operation != "" {
		prefix = fmt.Sprintf("%s during %s", prefix, e.Operation)
	}
	if e.StatusCode > 0 {
		prefix = fmt.Sprintf("%s %d", prefix, e.StatusCode)
	}
	if e.RetryExhausted {
		return fmt.Sprintf("%s: retries exhausted after %d attempts: %s", prefix, e.Attempts, e.Message)
	}
	return fmt.Sprintf("%s: %s", prefix, e.Message)
}

// Temporary returns true if the error is likely temporary and retryable
func (e *APIError) Temporary() bool {
	if e == nil {
		return false
	}
	if e.Kind == ErrorKindRequest {
		return true
	}
	return e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

func (e *RetryExhaustedError) Error() string {
	if e.Operation != "" {
		return fmt.Sprintf("secure-sbom API error during %s: retries exhausted after %d attempts: %v", e.Operation, e.Attempts, e.Err)
	}
	return fmt.Sprintf("secure-sbom API error: retries exhausted after %d attempts: %v", e.Attempts, e.Err)
}

func (e *RetryExhaustedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func NewClient(config *Config) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	cfg := *config

	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = UserAgent
	}

	var httpClient = cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: cfg.Timeout,
		}
	}

	return &Client{
		config:     &cfg,
		httpClient: httpClient,
	}, nil
}

func validateConfig(config *Config) error {
	if config.APIKey == "" {
		return fmt.Errorf("APIKey is required")
	}

	if config.BaseURL == "" {
		return fmt.Errorf("BaseURL is required")
	}

	if _, err := url.Parse(config.BaseURL); err != nil {
		return fmt.Errorf("invalid BaseURL: %w", err)
	}

	if config.Timeout < 0 {
		return fmt.Errorf("timeout cannot be negative")
	}

	return nil
}

func (c *Client) buildURL(endpoint string) string {
	baseURL := strings.TrimSuffix(c.config.BaseURL, "/")
	endpoint = strings.TrimPrefix(endpoint, "/")
	return fmt.Sprintf("%s/%s", baseURL, endpoint)
}

func (c *Client) doRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Response, error) {
	url := c.buildURL(endpoint)
	operation := requestOperation(method, endpoint)

	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, &APIError{
				Message:   "failed to encode request body",
				Operation: operation,
				Kind:      ErrorKindInputValidation,
			}
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, &APIError{
			Message:   "failed to create request",
			Operation: operation,
			Kind:      ErrorKindInputValidation,
		}
	}

	// Set authentication and headers
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, requestError(operation, err)
	}

	// Handle HTTP error status codes
	if resp.StatusCode >= 400 {
		defer func() {
			_ = resp.Body.Close()
		}()

		apiErr := &APIError{
			StatusCode: resp.StatusCode,
			Message:    http.StatusText(resp.StatusCode),
			Operation:  operation,
			Kind:       responseErrorKind(resp.StatusCode),
			RetryAfter: retryAfterFromHeaders(resp.Header, time.Now()),
		}

		// Try to parse structured error response
		if bodyBytes, err := io.ReadAll(resp.Body); err == nil && len(bodyBytes) > 0 {
			var errorResp struct {
				Message   string `json:"message"`
				Details   string `json:"details"`
				RequestID string `json:"request_id"`
				Error     string `json:"error"` // Alternative field name
			}

			if json.Unmarshal(bodyBytes, &errorResp) == nil {
				if errorResp.Message != "" {
					apiErr.Message = errorResp.Message
				} else if errorResp.Error != "" {
					apiErr.Message = errorResp.Error
				}
				apiErr.Details = errorResp.Details
				apiErr.RequestID = errorResp.RequestID
			}
		}

		return nil, apiErr
	}

	return resp, nil
}

func requestOperation(method, endpoint string) string {
	return fmt.Sprintf("%s /%s", method, strings.TrimPrefix(endpoint, "/"))
}

func requestError(operation string, err error) error {
	apiErr := &APIError{
		Message:   "request failed",
		Operation: operation,
		Kind:      ErrorKindRequest,
	}

	if errors.Is(err, context.Canceled) {
		apiErr.Message = "request canceled"
		apiErr.Kind = ErrorKindInputValidation
	} else if errors.Is(err, context.DeadlineExceeded) || isRetryableNetworkError(err) {
		apiErr.Message = "temporary request failure"
	} else {
		apiErr.Kind = ErrorKindResponse
	}

	return apiErr
}

func isRetryableNetworkError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	errText := strings.ToLower(err.Error())
	return strings.Contains(errText, "connection reset") ||
		strings.Contains(errText, "connection refused") ||
		strings.Contains(errText, "broken pipe") ||
		strings.Contains(errText, "unexpected eof")
}

func responseErrorKind(statusCode int) string {
	switch statusCode {
	case http.StatusTooManyRequests:
		return ErrorKindRateLimit
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrorKindAuthorization
	default:
		return ErrorKindResponse
	}
}

func retryAfterFromHeaders(headers http.Header, now time.Time) time.Duration {
	value := strings.TrimSpace(headers.Get("Retry-After"))
	if value != "" {
		if seconds, err := time.ParseDuration(value + "s"); err == nil && seconds > 0 {
			return seconds
		}
		if retryAt, err := http.ParseTime(value); err == nil && retryAt.After(now) {
			return retryAt.Sub(now)
		}
	}

	reset := strings.TrimSpace(headers.Get("X-RateLimit-Reset"))
	if reset == "" {
		return 0
	}
	if unixSeconds, err := strconv.ParseInt(reset, 10, 64); err == nil {
		resetAt := time.Unix(unixSeconds, 0)
		if resetAt.After(now) {
			return resetAt.Sub(now)
		}
		return 0
	}
	resetAt, err := time.Parse(time.RFC3339, reset)
	if err == nil && resetAt.After(now) {
		return resetAt.Sub(now)
	}
	return 0
}

func (c *Client) HealthCheck(ctx context.Context) error {
	resp, err := c.doRequest(ctx, "GET", API_ENDPOINT_HEALTHCHECK, nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	return nil
}

func (c *Client) ListKeys(ctx context.Context) (*KeyListResponse, error) {
	resp, err := c.doRequest(ctx, "GET", API_VERSION+API_ENDPOINT_KEYS, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse as array of API key items
	var apiKeys []ListKeysAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiKeys); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to GeneratedKey
	keys := make([]GenerateKeyCMDResponse, len(apiKeys))
	for i, apiKey := range apiKeys {
		keys[i] = GenerateKeyCMDResponse{
			ID:              apiKey.ID,
			CreatedAt:       apiKey.CreatedAt,
			Algorithm:       apiKey.Algorithm,
			Backend:         apiKey.Backend,
			KMSPath:         apiKey.KMSPath,
			ProtectionLevel: apiKey.ProtectionLevel,
			Purpose:         apiKey.Purpose,
		}
	}

	return &KeyListResponse{Keys: keys}, nil
}

func (c *Client) GenerateKey(ctx context.Context) (*GenerateKeyCMDResponse, error) {
	// Default behavior: no backend specified → server uses default (HSM/KMS)
	return c.generateKey(ctx, "")
}

func (c *Client) GenerateKeyWithBackend(ctx context.Context, backend string) (*GenerateKeyCMDResponse, error) {
	return c.generateKey(ctx, backend)
}

func (c *Client) generateKey(ctx context.Context, backend string) (*GenerateKeyCMDResponse, error) {
	var body interface{}

	if backend != "" {
		body = generateKeyRequest{Backend: backend}
	} else {
		body = nil
	}

	resp, err := c.doRequest(ctx, HTTP_METHOD_POST, API_VERSION+API_ENDPOINT_KEYS, body)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var apiResp GenerateKeyAPIReponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &GenerateKeyCMDResponse{
		ID:              apiResp.KeyID,
		CreatedAt:       apiResp.CreatedAt,
		PublicKey:       apiResp.PublicKey,
		Algorithm:       apiResp.Algorithm,
		Backend:         apiResp.Backend,
		ProtectionLevel: apiResp.ProtectionLevel,
		Purpose:         apiResp.Purpose,
	}, nil
}

// GetPublicKey retrieves the public key for a specific key ID
func (c *Client) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	if keyID == "" {
		return "", fmt.Errorf("keyID is required")
	}

	endpoint := API_VERSION + API_ENDPOINT_KEYS + "/public?key_id=" + keyID
	resp, err := c.doRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get public key: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read the PEM content as plain text
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return string(body), nil
}

func (c *Client) SignSBOM(ctx context.Context, keyID string, sbom interface{}) (*SignResultAPIResponseV2, error) {
	// Default behavior: embedded signature, no extras
	return c.signSBOM(ctx, keyID, sbom, SignOptions{})
}

func (c *Client) SignSBOMWithOptions(ctx context.Context, keyID string, sbom interface{}, opts SignOptions) (*SignResultAPIResponseV2, error) {
	return c.signSBOM(ctx, keyID, sbom, opts)
}

func (c *Client) SignDigest(ctx context.Context, req SignDigestRequest) (*SignDigestResponse, error) {
	if req.KeyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}
	if req.Digest == "" {
		return nil, fmt.Errorf("digestB64 is required")
	}
	if req.HashAlgorithm == "" {
		return nil, fmt.Errorf("hashAlgorithm is required")
	}

	endpoint := API_VERSION + API_ENDPOING_DIGEST + "/sign"

	resp, err := c.doRequest(ctx, http.MethodPost, endpoint, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sign digest: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var result SignDigestResponse
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode digest sign response: %w", err)
	}

	return &result, nil
}

func (c *Client) signSBOM(ctx context.Context, keyID string, sbom interface{}, opts SignOptions) (*SignResultAPIResponseV2, error) {
	if keyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}
	if sbom == nil {
		return nil, fmt.Errorf("sbom is required")
	}

	endpoint := API_VERSION_V2 + API_ENDPOINT_SBOM + "/sign"

	reqBody := struct {
		KeyID    string      `json:"key_id"`
		SBOM     interface{} `json:"sbom"`
		Pretty   bool        `json:"pretty,omitempty"`
		Detached bool        `json:"detached,omitempty"`
	}{
		KeyID:    keyID,
		SBOM:     sbom,
		Pretty:   opts.Pretty,
		Detached: opts.Detached,
	}

	resp, err := c.doRequest(ctx, http.MethodPost, endpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to sign SBOM: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var result SignResultAPIResponseV2
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode sign response: %w", err)
	}

	return &result, nil
}

// VerifySBOM verifies a signed SBOM using the specified key
func (c *Client) VerifySBOM(ctx context.Context, req VerifyCMDRequest) (*VerifyResultCMDResponse, error) {
	if req.KeyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}
	if req.SBOM == nil {
		return nil, fmt.Errorf("sbom is required for verification")
	}

	sbom, err := normalizeVerifySBOM(req.SBOM)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf(API_VERSION_V2 + API_ENDPOINT_SBOM + "/verify")

	reqBody := VerifyAPIRequestV2{
		KeyID: req.KeyID,
		SBOM:  sbom,
	}

	if req.SignatureB64 != "" {
		reqBody.SignatureB64 = req.SignatureB64
	}

	resp, err := c.doRequest(ctx, http.MethodPost, endpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to verify SBOM: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var apiResp VerifyResultAPIResponseV2
		err = json.Unmarshal(bodyBytes, &apiResp)
		if err != nil {
			return nil, fmt.Errorf("failed to decode success response: %w", err)
		}

		return &VerifyResultCMDResponse{
			Valid:     true,
			Code:      apiResp.Code,
			Message:   apiResp.Message,
			KeyID:     reqBody.KeyID,
			Timestamp: time.Now(),
		}, nil
	default:
		var apiResp VerifyResultAPIResponseV2
		err = json.Unmarshal(bodyBytes, &apiResp)
		if err != nil {
			return nil, fmt.Errorf("failed to decode error response: %w", err)
		}

		return &VerifyResultCMDResponse{
			Valid:     false,
			Code:      apiResp.Code,
			Message:   apiResp.Message,
			KeyID:     reqBody.KeyID,
			Timestamp: time.Now(),
		}, nil
	}
}
