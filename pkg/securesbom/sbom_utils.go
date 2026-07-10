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
	"bytes"
	"encoding/json"
	"fmt"
)

// GetSignatureValue returns the signature value as a string for convenience.
func (sr SignResultAPIResponseV2) GetSignatureValue() string {
	if sr.Signature != "" {
		return sr.Signature
	}
	return sr.SignatureB64
}

// GetSignatureAlgorithm returns the signature algorithm.
func (sr SignResultAPIResponseV2) GetSignatureAlgorithm() string {
	return sr.Algorithm
}

// GetSignedSBOMBytes returns the signed SBOM payload as JSON bytes.
func (sr SignResultAPIResponseV2) GetSignedSBOMBytes() ([]byte, error) {
	return sr.SignedSBOM, nil
}

// HasSignature returns true if the response contains a detached signature.
func (sr SignResultAPIResponseV2) HasSignature() bool {
	return sr.Signature != "" || sr.SignatureB64 != ""
}

func normalizeVerifySBOM(sbom interface{}) (interface{}, error) {
	switch value := sbom.(type) {
	case SignResultAPIResponseV2:
		return signedSBOMFromSignResponse(value)
	case *SignResultAPIResponseV2:
		if value == nil {
			return nil, fmt.Errorf("sbom is required for verification")
		}
		return signedSBOMFromSignResponse(*value)
	case json.RawMessage:
		return normalizeVerifyJSON(value, sbom)
	case []byte:
		return normalizeVerifyJSON(value, sbom)
	case string:
		return normalizeVerifyJSON([]byte(value), sbom)
	default:
		raw, err := json.Marshal(sbom)
		if err != nil {
			return sbom, nil
		}
		return normalizeVerifyJSON(raw, sbom)
	}
}

func signedSBOMFromSignResponse(response SignResultAPIResponseV2) (interface{}, error) {
	if len(bytes.TrimSpace(response.SignedSBOM)) > 0 {
		return response.SignedSBOM, nil
	}

	if response.Detached || response.SignatureB64 != "" || response.Signature != "" {
		return nil, fmt.Errorf("detached signature verification requires the original SBOM and signature_b64")
	}

	return nil, fmt.Errorf("sign response does not include signed_sbom for verification")
}

func normalizeVerifyJSON(raw []byte, original interface{}) (interface{}, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return original, nil
	}

	var envelope struct {
		SignedSBOM   json.RawMessage `json:"signed_sbom"`
		SBOMType     string          `json:"sbom_type"`
		Signature    string          `json:"signature"`
		SignatureB64 string          `json:"signature_b64"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return original, nil
	}

	if len(bytes.TrimSpace(envelope.SignedSBOM)) > 0 {
		return envelope.SignedSBOM, nil
	}

	if envelope.SBOMType != "" {
		return nil, fmt.Errorf("detached signature verification requires the original SBOM and signature_b64")
	}

	return original, nil
}
