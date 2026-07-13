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
	"strings"
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

func normalizeVerifySignatureB64(signature string) (string, error) {
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return "", nil
	}

	var signatureString string
	if err := json.Unmarshal([]byte(signature), &signatureString); err == nil {
		return strings.TrimSpace(signatureString), nil
	}
	if !json.Valid([]byte(signature)) {
		return signature, nil
	}

	var envelope struct {
		SignatureB64 string `json:"signature_b64"`
		Signature    string `json:"signature"`
	}
	if err := json.Unmarshal([]byte(signature), &envelope); err != nil {
		return "", fmt.Errorf("signature payload must be a JSON object with signature_b64 or signature")
	}

	if strings.TrimSpace(envelope.SignatureB64) != "" {
		return strings.TrimSpace(envelope.SignatureB64), nil
	}
	if strings.TrimSpace(envelope.Signature) != "" {
		return strings.TrimSpace(envelope.Signature), nil
	}

	return "", fmt.Errorf("signature payload does not include signature_b64 or signature")
}

func normalizeVerifyDetachedSignature(sbom interface{}, signature string) (interface{}, string, error) {
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return sbom, "", nil
	}

	signatureSBOM, ok, err := cycloneDXSBOMWithDetachedSignature(sbom, signature)
	if err != nil {
		return nil, "", err
	}
	if ok {
		return signatureSBOM, "", nil
	}

	if !json.Valid([]byte(signature)) && isCycloneDXSBOM(sbom) {
		return nil, "", fmt.Errorf("CycloneDX detached verification requires the detached signing response JSON, not only the signature value")
	}

	signatureB64, err := normalizeVerifySignatureB64(signature)
	if err != nil {
		return nil, "", err
	}
	return sbom, signatureB64, nil
}

func cycloneDXSBOMWithDetachedSignature(sbom interface{}, signature string) (interface{}, bool, error) {
	if !json.Valid([]byte(signature)) {
		return sbom, false, nil
	}

	var envelope struct {
		SignedSBOM json.RawMessage `json:"signed_sbom"`
		SBOMType   string          `json:"sbom_type"`
		Detached   bool            `json:"detached"`
	}
	if err := json.Unmarshal([]byte(signature), &envelope); err != nil {
		return nil, false, fmt.Errorf("signature payload must be a JSON object with signature_b64, signature, or CycloneDX signed_sbom")
	}
	if !envelope.Detached || !strings.EqualFold(envelope.SBOMType, "cyclonedx") || len(bytes.TrimSpace(envelope.SignedSBOM)) == 0 {
		return sbom, false, nil
	}

	var signatureObject map[string]interface{}
	if err := json.Unmarshal(envelope.SignedSBOM, &signatureObject); err != nil {
		return nil, false, fmt.Errorf("failed to decode CycloneDX detached signature object: %w", err)
	}
	signatureValue, ok := signatureObject["value"].(string)
	if !ok || strings.TrimSpace(signatureValue) == "" {
		return nil, false, fmt.Errorf("CycloneDX detached signature object does not include value")
	}

	rawSBOM, err := json.Marshal(sbom)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode SBOM for CycloneDX detached verification: %w", err)
	}
	var sbomObject map[string]interface{}
	if err := json.Unmarshal(rawSBOM, &sbomObject); err != nil {
		return nil, false, fmt.Errorf("failed to decode SBOM for CycloneDX detached verification: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(sbomObject["bomFormat"])), "CycloneDX") {
		return nil, false, fmt.Errorf("CycloneDX detached signature payload requires a CycloneDX SBOM")
	}

	sbomObject["signature"] = signatureObject
	return sbomObject, true, nil
}

func isCycloneDXSBOM(sbom interface{}) bool {
	rawSBOM, err := json.Marshal(sbom)
	if err != nil {
		return false
	}
	var sbomObject map[string]interface{}
	if err := json.Unmarshal(rawSBOM, &sbomObject); err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(fmt.Sprint(sbomObject["bomFormat"])), "CycloneDX")
}
