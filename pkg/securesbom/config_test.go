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
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestConfigBuilder_WithBaseURL(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		expected string
	}{
		{
			name:     "valid URL",
			baseURL:  "https://api.example.com",
			expected: "https://api.example.com",
		},
		{
			name:     "empty URL",
			baseURL:  "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewConfigBuilder()
			result := builder.WithBaseURL(tt.baseURL)

			if result != builder {
				t.Error("expected fluent interface")
			}

			config := builder.Build()
			if config.BaseURL != tt.expected {
				t.Errorf("expected BaseURL to be %q, got %q", tt.expected, config.BaseURL)
			}
		})
	}
}

func TestConfigBuilder_WithAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   string
		expected string
	}{
		{
			name:     "valid API key",
			apiKey:   "test-api-key",
			expected: "test-api-key",
		},
		{
			name:     "empty API key",
			apiKey:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewConfigBuilder()
			result := builder.WithAPIKey(tt.apiKey)

			if result != builder {
				t.Error("expected fluent interface")
			}

			config := builder.Build()
			if config.APIKey != tt.expected {
				t.Errorf("expected APIKey to be %q, got %q", tt.expected, config.APIKey)
			}
		})
	}
}

func TestConfigBuilder_WithTimeout(t *testing.T) {
	tests := []struct {
		name     string
		timeout  time.Duration
		expected time.Duration
	}{
		{
			name:     "45 second timeout",
			timeout:  45 * time.Second,
			expected: 45 * time.Second,
		},
		{
			name:     "zero timeout",
			timeout:  0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewConfigBuilder()
			result := builder.WithTimeout(tt.timeout)

			if result != builder {
				t.Error("expected fluent interface")
			}

			config := builder.Build()
			if config.Timeout != tt.expected {
				t.Errorf("expected Timeout to be %v, got %v", tt.expected, config.Timeout)
			}
		})
	}
}

func TestLoadSBOMFromReader(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectError  bool
		errorMsg     string
		expectedName interface{} // Use interface{} to handle different types
	}{
		{
			name:         "valid JSON",
			input:        `{"name": "test", "version": "1.0"}`,
			expectError:  false,
			expectedName: "test",
		},
		{
			name:        "empty data",
			input:       "",
			expectError: true,
			errorMsg:    "no data provided",
		},
		{
			name:        "invalid JSON",
			input:       "invalid json",
			expectError: true,
			errorMsg:    "failed to parse SBOM JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			sbom, err := LoadSBOMFromReader(reader)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if sbom == nil {
				t.Error("expected non-nil SBOM")
			}

			if tt.expectedName != nil {
				data := sbom.Data().(map[string]interface{})
				if data["name"] != tt.expectedName {
					t.Errorf("expected name %v, got %v", tt.expectedName, data["name"])
				}
			}
		})
	}
}

func TestWithRetry(t *testing.T) {
	tests := []struct {
		name          string
		maxAttempts   int
		initialWait   time.Duration
		setupFunc     func() (func() error, *int) // Returns function to retry and call counter
		expectError   bool
		expectedCalls int
		errorMsg      string
	}{
		{
			name:        "succeeds immediately",
			maxAttempts: 3,
			initialWait: time.Millisecond,
			setupFunc: func() (func() error, *int) {
				callCount := 0
				return func() error {
					callCount++
					return nil // Success on first try
				}, &callCount
			},
			expectError:   false,
			expectedCalls: 1,
		},
		{
			name:        "retries on temporary error",
			maxAttempts: 3,
			initialWait: time.Millisecond,
			setupFunc: func() (func() error, *int) {
				callCount := 0
				return func() error {
					callCount++
					if callCount < 2 {
						return &APIError{StatusCode: 500, Message: "server error"}
					}
					return nil // Success on second try
				}, &callCount
			},
			expectError:   false,
			expectedCalls: 2,
		},
		{
			name:        "stops on non-temporary error",
			maxAttempts: 3,
			initialWait: time.Millisecond,
			setupFunc: func() (func() error, *int) {
				callCount := 0
				return func() error {
					callCount++
					return &APIError{StatusCode: 400, Message: "bad request"}
				}, &callCount
			},
			expectError:   true,
			expectedCalls: 1,
		},
		{
			name:        "fails after max attempts",
			maxAttempts: 2,
			initialWait: time.Millisecond,
			setupFunc: func() (func() error, *int) {
				callCount := 0
				return func() error {
					callCount++
					return &APIError{StatusCode: 500, Message: "server error"}
				}, &callCount
			},
			expectError:   true,
			expectedCalls: 2,
			errorMsg:      "retries exhausted after 2 attempts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			config := RetryConfig{
				MaxAttempts: tt.maxAttempts,
				InitialWait: tt.initialWait,
				MaxWait:     10 * time.Millisecond,
				Multiplier:  2.0,
			}

			retryFunc, callCount := tt.setupFunc()

			err := WithRetry(ctx, config, retryFunc)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if *callCount != tt.expectedCalls {
				t.Errorf("expected %d calls, got %d", tt.expectedCalls, *callCount)
			}
		})
	}
}

func TestWithRetry_DoesNotRetryNonAPIError(t *testing.T) {
	callCount := 0

	err := WithRetry(context.Background(), RetryConfig{
		MaxAttempts: 3,
		InitialWait: time.Millisecond,
		MaxWait:     time.Millisecond,
		Multiplier:  2,
	}, func() error {
		callCount++
		return errors.New("permanent local failure")
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if callCount != 1 {
		t.Fatalf("expected 1 call, got %d", callCount)
	}
}

func TestWithRetry_RetryExhaustedShape(t *testing.T) {
	err := WithRetry(context.Background(), RetryConfig{
		MaxAttempts: 2,
		InitialWait: time.Millisecond,
		MaxWait:     time.Millisecond,
		Multiplier:  2,
	}, func() error {
		return &APIError{
			StatusCode: http.StatusTooManyRequests,
			Message:    "rate limited",
			Operation:  "GET /v0/keys",
			Kind:       ErrorKindRateLimit,
		}
	})

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T", err)
	}
	if !apiErr.RetryExhausted {
		t.Fatal("expected RetryExhausted to be true")
	}
	if apiErr.Kind != ErrorKindRetryExhausted {
		t.Fatalf("expected kind %q, got %q", ErrorKindRetryExhausted, apiErr.Kind)
	}
	if apiErr.Attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", apiErr.Attempts)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected status %d, got %d", http.StatusTooManyRequests, apiErr.StatusCode)
	}
	if apiErr.Operation != "GET /v0/keys" {
		t.Fatalf("expected operation context, got %q", apiErr.Operation)
	}
}

func TestWithRetry_UsesBoundedRateLimitDelay(t *testing.T) {
	var waits []time.Duration
	after := func(wait time.Duration) <-chan time.Time {
		waits = append(waits, wait)
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}

	callCount := 0
	err := withRetry(context.Background(), RetryConfig{
		MaxAttempts: 2,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     50 * time.Millisecond,
		Multiplier:  2,
	}, func() error {
		callCount++
		return &APIError{
			StatusCode: http.StatusTooManyRequests,
			Message:    "rate limited",
			Kind:       ErrorKindRateLimit,
			RetryAfter: 2 * time.Second,
		}
	}, after)

	if err == nil {
		t.Fatal("expected error")
	}
	if callCount != 2 {
		t.Fatalf("expected 2 calls, got %d", callCount)
	}
	if len(waits) != 1 {
		t.Fatalf("expected 1 wait, got %d", len(waits))
	}
	if waits[0] != 50*time.Millisecond {
		t.Fatalf("expected capped wait of 50ms, got %s", waits[0])
	}
}
