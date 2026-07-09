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

package securesbom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"
)

type ConfigBuilder struct {
	config Config
}

type SBOM struct {
	data interface{}
}

type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
	Multiplier  float64
}

type ClientOption func(*Config)

type RetryingClient struct {
	client      *Client
	retryConfig RetryConfig
}

func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{}
}

func (b *ConfigBuilder) WithBaseURL(baseURL string) *ConfigBuilder {
	b.config.BaseURL = baseURL
	return b
}

func (b *ConfigBuilder) WithAPIKey(apiKey string) *ConfigBuilder {
	b.config.APIKey = apiKey
	return b
}

func (b *ConfigBuilder) WithTimeout(timeout time.Duration) *ConfigBuilder {
	b.config.Timeout = timeout
	return b
}

func (b *ConfigBuilder) WithHTTPClient(client HTTPClient) *ConfigBuilder {
	b.config.HTTPClient = client
	return b
}

func (b *ConfigBuilder) WithUserAgent(userAgent string) *ConfigBuilder {
	b.config.UserAgent = userAgent
	return b
}

func (b *ConfigBuilder) FromEnv() *ConfigBuilder {
	if apiKey := os.Getenv("SECURE_SBOM_API_KEY"); apiKey != "" {
		b.config.APIKey = apiKey
	}
	if baseURL := os.Getenv("SECURE_SBOM_BASE_URL"); baseURL != "" {
		b.config.BaseURL = baseURL
	} else {
		b.config.BaseURL = DEFAULT_SECURE_SBOM_BASE_URL
	}
	return b
}

func (b *ConfigBuilder) Build() *Config {
	// Return a copy to prevent external mutation
	config := b.config
	return &config
}

func (b *ConfigBuilder) BuildClient() (*Client, error) {
	return NewClient(b.Build())
}

func NewSBOM(data interface{}) *SBOM {
	return &SBOM{data: data}
}

func LoadSBOMFromReader(reader io.Reader) (*SBOM, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("no data provided")
	}

	var sbomData interface{}
	if err := json.Unmarshal(data, &sbomData); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	return &SBOM{data: sbomData}, nil
}

func LoadSBOMFromFile(filePath string) (*SBOM, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer func() {
		_ = file.Close()
	}()

	return LoadSBOMFromReader(file)
}

func (s *SBOM) Data() interface{} {
	if s == nil {
		return nil
	}

	return s.data
}

func (s *SBOM) WriteToWriter(writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(s.data)
}

func (s *SBOM) WriteToFile(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer func() {
		_ = file.Close()
	}()

	return s.WriteToWriter(file)
}

func (s *SBOM) String() string {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error marshaling SBOM: %v", err)
	}
	return string(data)
}

func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 3,
		InitialWait: 1 * time.Second,
		MaxWait:     10 * time.Second,
		Multiplier:  2.0,
	}
}

func WithRetry(ctx context.Context, config RetryConfig, fn func() error) error {
	return withRetry(ctx, config, fn, time.After)
}

func withRetry(ctx context.Context, config RetryConfig, fn func() error, after func(time.Duration) <-chan time.Time) error {
	var lastErr error
	config = normalizeRetryConfig(config)

	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		if err := fn(); err != nil {
			lastErr = err

			if !isRetryableError(err) {
				return err
			}

			// Don't wait after the last attempt
			if attempt == config.MaxAttempts-1 {
				break
			}

			waitTime := retryDelay(config, attempt, err)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-after(waitTime):
				// Continue to next attempt
			}
		} else {
			return nil // Success
		}
	}

	var apiErr *APIError
	if errors.As(lastErr, &apiErr) {
		exhausted := *apiErr
		exhausted.Kind = ErrorKindRetryExhausted
		exhausted.RetryExhausted = true
		exhausted.Attempts = config.MaxAttempts
		return &exhausted
	}

	return &RetryExhaustedError{
		Attempts: config.MaxAttempts,
		Err:      lastErr,
	}
}

func normalizeRetryConfig(config RetryConfig) RetryConfig {
	defaults := DefaultRetryConfig()
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = defaults.MaxAttempts
	}
	if config.InitialWait <= 0 {
		config.InitialWait = defaults.InitialWait
	}
	if config.MaxWait <= 0 {
		config.MaxWait = defaults.MaxWait
	}
	if config.Multiplier < 1 {
		config.Multiplier = defaults.Multiplier
	}
	return config
}

func isRetryableError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Temporary()
	}
	return false
}

func retryDelay(config RetryConfig, attempt int, err error) time.Duration {
	waitTime := time.Duration(float64(config.InitialWait) *
		math.Pow(config.Multiplier, float64(attempt)))

	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter > waitTime {
		waitTime = apiErr.RetryAfter
	}

	if waitTime > config.MaxWait {
		return config.MaxWait
	}
	return waitTime
}

func WithRetryingClient(client *Client, retryConfig RetryConfig) *RetryingClient {
	return &RetryingClient{
		client:      client,
		retryConfig: retryConfig,
	}
}

func (r *RetryingClient) HealthCheck(ctx context.Context) error {
	return WithRetry(ctx, r.retryConfig, func() error {
		return r.client.HealthCheck(ctx)
	})
}

func (r *RetryingClient) ListKeys(ctx context.Context) (*KeyListResponse, error) {
	var result *KeyListResponse
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.ListKeys(ctx)
		return err
	})
	return result, err
}

func (r *RetryingClient) GenerateKey(ctx context.Context) (*GenerateKeyCMDResponse, error) {
	var result *GenerateKeyCMDResponse
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.GenerateKey(ctx)
		return err
	})
	return result, err
}

func (r *RetryingClient) GenerateKeyWithBackend(ctx context.Context, backend string) (*GenerateKeyCMDResponse, error) {
	var result *GenerateKeyCMDResponse
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.GenerateKeyWithBackend(ctx, backend)
		return err
	})
	return result, err
}

func (r *RetryingClient) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	var result string
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.GetPublicKey(ctx, keyID)
		return err
	})
	return result, err
}

func (r *RetryingClient) SignSBOM(ctx context.Context, keyID string, sbom interface{}) (*SignResultAPIResponseV2, error) {
	var result *SignResultAPIResponseV2
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.SignSBOM(ctx, keyID, sbom)
		return err
	})
	return result, err
}

func (r *RetryingClient) SignSBOMWithOptions(ctx context.Context, keyID string, sbom interface{}, opts SignOptions) (*SignResultAPIResponseV2, error) {
	var result *SignResultAPIResponseV2
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.SignSBOMWithOptions(ctx, keyID, sbom, opts)
		return err
	})
	return result, err
}

func (r *RetryingClient) SignDigest(ctx context.Context, req SignDigestRequest) (*SignDigestResponse, error) {
	var result *SignDigestResponse
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.SignDigest(ctx, req)
		return err
	})
	return result, err
}

func (r *RetryingClient) VerifySBOM(ctx context.Context, req VerifyCMDRequest) (*VerifyResultCMDResponse, error) {
	var result *VerifyResultCMDResponse
	err := WithRetry(ctx, r.retryConfig, func() error {
		var err error
		result, err = r.client.VerifySBOM(ctx, req)
		return err
	})
	return result, err
}
