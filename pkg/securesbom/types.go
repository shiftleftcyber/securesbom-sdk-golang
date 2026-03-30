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
	"encoding/json"
	"net/http"
	"time"
)

// Config holds configuration for the Secure SBOM API client
type Config struct {
	BaseURL    string
	APIKey     string
	HTTPClient HTTPClient
	Timeout    time.Duration
	UserAgent  string
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// SecureSBOM Keys

type GenerateKeyCMDResponse struct {
	ID              string    `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	Algorithm       string    `json:"algorithm"`
	PublicKey       string    `json:"public_key,omitempty"`
	Backend         string    `json:"backend,omitempty"`
	KMSPath         string    `json:"kms_path,omitempty"`
	ProtectionLevel string    `json:"protection_level,omitempty"`
	Purpose         string    `json:"purpose,omitempty"`
}

type KeyListResponse struct {
	Keys []GenerateKeyCMDResponse `json:"keys"`
}

type ListKeysAPIResponse struct {
	ID              string    `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	Algorithm       string    `json:"algorithm"`
	Backend         string    `json:"backend"`
	KMSPath         string    `json:"kms_path,omitempty"`
	ProtectionLevel string    `json:"protection_level,omitempty"`
	Purpose         string    `json:"purpose,omitempty"`
}

type GenerateKeyAPIReponse struct {
	KeyID           string    `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	Algorithm       string    `json:"algorithm"`
	PublicKey       string    `json:"public_key"`
	Backend         string    `json:"backend"`
	KMSPath         string    `json:"kms_path,omitempty"`
	ProtectionLevel string    `json:"protection_level,omitempty"`
	Purpose         string    `json:"purpose,omitempty"`
}

// Signing

type SignResultAPIResponseV2 struct {
	SignedSBOM   json.RawMessage `json:"signed_sbom,omitempty"`
	Algorithm    string          `json:"algorithm"`
	Detached     bool            `json:"detached"`
	SBOMType     string          `json:"sbom_type,omitempty"`
	Signature    string          `json:"signature,omitempty"`
	SignatureB64 string          `json:"signature_b64,omitempty"`
}

type SignDigestRequest struct {
	Digest        string `json:"digest"`
	HashAlgorithm string `json:"hash_algorithm"`
	KeyID         string `json:"key_id"`
}

type SignDigestResponse struct {
	HashAlgorithm      string `json:"hash_algorithm"`
	KeyID              string `json:"key_id"`
	Signature          string `json:"signature"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	PublicKey          any    `json:"publicKey,omitempty"`
}

// verification

type VerifyResultCMDResponse struct {
	Valid     bool      `json:"valid"`
	Code      string    `json:"code"`
	Message   string    `json:"message,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	Algorithm string    `json:"algorithm,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

type VerifyAPIRequestV2 struct {
	KeyID        string      `json:"key_id"`
	SBOM         interface{} `json:"sbom"`
	SignatureB64 string      `json:"signature_b64"`
}

type VerifyResultAPIResponseV2 struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type VerifyCMDRequest struct {
	KeyID        string      `json:"key_id"`
	SBOM         interface{} `json:"sbom"`
	SignatureB64 string      `json:"signature_b64,omitempty"`
}

type generateKeyRequest struct {
	Backend string `json:"backend,omitempty"`
}

type SignOptions struct {
	Detached bool
	Pretty   bool
}
