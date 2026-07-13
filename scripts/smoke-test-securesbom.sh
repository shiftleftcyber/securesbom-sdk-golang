#!/usr/bin/env bash
set -Euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"
OUT_DIR="${OUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/securesbom-smoke.XXXXXX")}"

CDX_SAMPLE="${CDX_SAMPLE:-${ROOT_DIR}/samples/cdx/sbomex-cdx.json}"
SPDX_SAMPLE="${SPDX_SAMPLE:-${ROOT_DIR}/samples/spdx/sbom-tool/sbomex-spdx.json}"
KEY_ID="${SECURE_SBOM_SIGNING_KEY_ID:-${KEY_ID:-}}"
SECURESBOM_VERIFIER_DIR="${SECURESBOM_VERIFIER_DIR:-${ROOT_DIR}/../securesbom-verifier}"
SECURESBOM_VERIFIER_BIN="${SECURESBOM_VERIFIER_BIN:-}"
CHECKS_PASSED=0
CHECKS_FAILED=0
FAILED_CHECKS=()

cleanup() {
	if [[ "${KEEP_SMOKE_OUTPUT:-0}" == "1" ]]; then
		printf 'Keeping smoke-test output in %s\n' "${OUT_DIR}"
		return
	fi
	rm -rf "${OUT_DIR}"
}
trap cleanup EXIT

usage() {
	cat <<'USAGE'
SecureSBOM SDK smoke test

Required environment:
  SECURE_SBOM_API_KEY           API key used by the example clients
  SECURE_SBOM_SIGNING_KEY_ID    Signing key ID used for SBOM and digest signing

Optional environment:
  SECURE_SBOM_BASE_URL          Custom API base URL
  OUT_DIR                       Directory for generated artifacts
  KEEP_SMOKE_OUTPUT=1           Keep generated artifacts after the run
  SKIP_BUILD=1                  Do not run make build-examples first
  CDX_SAMPLE                    CycloneDX sample path
  SPDX_SAMPLE                   SPDX sample path
  SECURESBOM_VERIFIER_DIR       securesbom-verifier checkout for digest verification
  SECURESBOM_VERIFIER_BIN       Prebuilt sbom-offline-verification binary

Run:
  SECURE_SBOM_API_KEY=... SECURE_SBOM_SIGNING_KEY_ID=... scripts/smoke-test-securesbom.sh
USAGE
}

log() {
	printf '\n==> %s\n' "$*"
}

fail() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

run() {
	printf '+'
	printf ' %q' "$@"
	printf '\n'
	"$@"
}

check() {
	local name="$1"
	shift

	log "${name}"
	if "$@"; then
		printf 'PASS: %s\n' "${name}"
		CHECKS_PASSED=$((CHECKS_PASSED + 1))
	else
		local status=$?
		printf 'FAIL: %s (exit %d)\n' "${name}" "${status}" >&2
		FAILED_CHECKS+=("${name}")
		CHECKS_FAILED=$((CHECKS_FAILED + 1))
	fi
}

assert_json_value() {
	local file="$1"
	local jq_filter="$2"
	local expected="$3"
	local actual

	actual="$(jq -r "${jq_filter}" "${file}")"
	[[ "${actual}" == "${expected}" ]] || fail "${file}: expected ${jq_filter} to be ${expected}, got ${actual}"
}

assert_json_nonempty() {
	local file="$1"
	local jq_filter="$2"

	jq -e "${jq_filter} | strings | length > 0" "${file}" >/dev/null ||
		fail "${file}: expected non-empty ${jq_filter}"
}

assert_file_contains() {
	local file="$1"
	local pattern="$2"

	grep -q "${pattern}" "${file}" || fail "${file}: expected to contain ${pattern}"
}

digest_b64() {
	local file="$1"
	shasum -a 256 "${file}" | awk '{print $1}' | xxd -r -p | base64 | tr -d '\n'
}

[[ "${1:-}" != "-h" && "${1:-}" != "--help" ]] || {
	usage
	exit 0
}

require_cmd jq
require_cmd shasum
require_cmd xxd
require_cmd base64
require_cmd go

[[ -n "${SECURE_SBOM_API_KEY:-}" ]] || fail "SECURE_SBOM_API_KEY is required"
[[ -n "${KEY_ID}" ]] || fail "SECURE_SBOM_SIGNING_KEY_ID or KEY_ID is required"
[[ -f "${CDX_SAMPLE}" ]] || fail "CycloneDX sample not found: ${CDX_SAMPLE}"
[[ -f "${SPDX_SAMPLE}" ]] || fail "SPDX sample not found: ${SPDX_SAMPLE}"

mkdir -p "${OUT_DIR}"

cd "${ROOT_DIR}"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
	log "Building example binaries"
	run make build-examples
fi

health_check() {
	run "${BIN_DIR}/healthcheck"
}

key_lookup() {
	run "${BIN_DIR}/keymgmt" public "${KEY_ID}" -output "${OUT_DIR}/public.pem" -quiet >"${OUT_DIR}/public.pem.stdout"
	if [[ -s "${OUT_DIR}/public.pem" ]]; then
		assert_file_contains "${OUT_DIR}/public.pem" "BEGIN PUBLIC KEY"
	else
		assert_file_contains "${OUT_DIR}/public.pem.stdout" "BEGIN PUBLIC KEY"
	fi
}

cyclonedx_embedded_sign() {
	run "${BIN_DIR}/sign" \
	-key-id "${KEY_ID}" \
	-sbom "${CDX_SAMPLE}" \
	-output "${OUT_DIR}/cyclonedx.embedded.response.json" \
	-quiet
	assert_json_value "${OUT_DIR}/cyclonedx.embedded.response.json" '.sbom_type' 'cyclonedx'
	assert_json_value "${OUT_DIR}/cyclonedx.embedded.response.json" '.detached' 'false'
	assert_json_nonempty "${OUT_DIR}/cyclonedx.embedded.response.json" '.signed_sbom.signature.value'
}

cyclonedx_embedded_verify_envelope() {
	[[ -f "${OUT_DIR}/cyclonedx.embedded.response.json" ]] || fail "missing CycloneDX embedded signing response"
	run "${BIN_DIR}/verify" \
	-key-id "${KEY_ID}" \
	-sbom "${OUT_DIR}/cyclonedx.embedded.response.json" \
	-quiet
}

cyclonedx_embedded_verify_raw_sbom() {
	[[ -f "${OUT_DIR}/cyclonedx.embedded.response.json" ]] || fail "missing CycloneDX embedded signing response"
	jq '.signed_sbom' "${OUT_DIR}/cyclonedx.embedded.response.json" >"${OUT_DIR}/cyclonedx.embedded.sbom.json"
	run "${BIN_DIR}/verify" \
	-key-id "${KEY_ID}" \
	-sbom "${OUT_DIR}/cyclonedx.embedded.sbom.json" \
	-quiet
}

cyclonedx_detached_sign() {
	run "${BIN_DIR}/sign" \
	-key-id "${KEY_ID}" \
	-sbom "${CDX_SAMPLE}" \
	-detached \
	-output "${OUT_DIR}/cyclonedx.detached.response.json" \
	-quiet
	assert_json_value "${OUT_DIR}/cyclonedx.detached.response.json" '.sbom_type' 'cyclonedx'
	assert_json_value "${OUT_DIR}/cyclonedx.detached.response.json" '.detached' 'true'
	assert_json_nonempty "${OUT_DIR}/cyclonedx.detached.response.json" '.signed_sbom.value'
}

cyclonedx_detached_verify_file() {
	[[ -f "${OUT_DIR}/cyclonedx.detached.response.json" ]] || fail "missing CycloneDX detached signing response"
	run "${BIN_DIR}/verify" \
	-key-id "${KEY_ID}" \
	-sbom "${CDX_SAMPLE}" \
	-signature "${OUT_DIR}/cyclonedx.detached.response.json" \
	-quiet
}

spdx_detached_sign() {
	run "${BIN_DIR}/sign" \
	-key-id "${KEY_ID}" \
	-sbom "${SPDX_SAMPLE}" \
	-output "${OUT_DIR}/spdx.detached.response.json" \
	-quiet
	assert_json_value "${OUT_DIR}/spdx.detached.response.json" '.sbom_type' 'spdx'
	assert_json_value "${OUT_DIR}/spdx.detached.response.json" '.detached' 'true'
	assert_json_nonempty "${OUT_DIR}/spdx.detached.response.json" '.signature_b64'
}

spdx_detached_verify_raw_signature() {
	[[ -f "${OUT_DIR}/spdx.detached.response.json" ]] || fail "missing SPDX detached signing response"
	run "${BIN_DIR}/verify" \
	-key-id "${KEY_ID}" \
	-sbom "${SPDX_SAMPLE}" \
	-signature "$(jq -r '.signature_b64' "${OUT_DIR}/spdx.detached.response.json")" \
	-quiet
}

spdx_detached_verify_json_string() {
	[[ -f "${OUT_DIR}/spdx.detached.response.json" ]] || fail "missing SPDX detached signing response"
	run "${BIN_DIR}/verify" \
	-key-id "${KEY_ID}" \
	-sbom "${SPDX_SAMPLE}" \
	-signature "$(cat "${OUT_DIR}/spdx.detached.response.json")" \
	-quiet
}

spdx_detached_verify_file() {
	[[ -f "${OUT_DIR}/spdx.detached.response.json" ]] || fail "missing SPDX detached signing response"
	run "${BIN_DIR}/verify" \
	-key-id "${KEY_ID}" \
	-sbom "${SPDX_SAMPLE}" \
	-signature "${OUT_DIR}/spdx.detached.response.json" \
	-quiet
}

digest_sign_cyclonedx() {
	local cdx_digest
	cdx_digest="$(digest_b64 "${CDX_SAMPLE}")"
	run "${BIN_DIR}/digest" \
	-key-id "${KEY_ID}" \
	-hash-algorithm sha256 \
	-digest "${cdx_digest}" \
	-output "${OUT_DIR}/cyclonedx.digest.response.json" \
	-pretty \
	-quiet
	assert_json_nonempty "${OUT_DIR}/cyclonedx.digest.response.json" '.signature'
	assert_json_value "${OUT_DIR}/cyclonedx.digest.response.json" '.hash_algorithm' 'sha256'
}

digest_verify_cyclonedx() {
	[[ -f "${OUT_DIR}/cyclonedx.digest.response.json" ]] || fail "missing CycloneDX digest signing response"
	[[ -s "${OUT_DIR}/public.pem" || -s "${OUT_DIR}/public.pem.stdout" ]] || fail "missing public key output"

	local public_key_path="${OUT_DIR}/public.pem"
	if [[ ! -s "${public_key_path}" ]]; then
		public_key_path="${OUT_DIR}/public.pem.stdout"
	fi

	local cdx_digest signature hash_algorithm signature_algorithm
	cdx_digest="$(digest_b64 "${CDX_SAMPLE}")"
	signature="$(jq -r '.signature' "${OUT_DIR}/cyclonedx.digest.response.json")"
	hash_algorithm="$(jq -r '.hash_algorithm' "${OUT_DIR}/cyclonedx.digest.response.json")"
	signature_algorithm="$(jq -r '.signature_algorithm' "${OUT_DIR}/cyclonedx.digest.response.json")"

	if [[ -n "${SECURESBOM_VERIFIER_BIN}" ]]; then
		run "${SECURESBOM_VERIFIER_BIN}" \
			--digest "${cdx_digest}" \
			--signature "${signature}" \
			--pubkey "${public_key_path}" \
			--hash-algorithm "${hash_algorithm}" \
			--signature-algorithm "${signature_algorithm}"
		return
	fi

	[[ -d "${SECURESBOM_VERIFIER_DIR}" ]] || fail "securesbom-verifier checkout not found: ${SECURESBOM_VERIFIER_DIR}"
	(
		cd "${SECURESBOM_VERIFIER_DIR}"
		run env GOEXPERIMENT=jsonv2 go run ./cmd/sbom-offline-verification \
			--digest "${cdx_digest}" \
			--signature "${signature}" \
			--pubkey "${public_key_path}" \
			--hash-algorithm "${hash_algorithm}" \
			--signature-algorithm "${signature_algorithm}"
	)
}

check "Health check" health_check
check "Key lookup" key_lookup
check "CycloneDX embedded signing" cyclonedx_embedded_sign
check "CycloneDX embedded verification from signing response envelope" cyclonedx_embedded_verify_envelope
check "CycloneDX embedded verification from raw signed_sbom" cyclonedx_embedded_verify_raw_sbom
check "CycloneDX detached signing" cyclonedx_detached_sign
check "CycloneDX detached verification from detached response file" cyclonedx_detached_verify_file
check "SPDX detached signing" spdx_detached_sign
check "SPDX detached verification from raw signature_b64" spdx_detached_verify_raw_signature
check "SPDX detached verification from detached response JSON string" spdx_detached_verify_json_string
check "SPDX detached verification from detached response file" spdx_detached_verify_file
check "Digest signing for CycloneDX sample" digest_sign_cyclonedx
check "Digest offline verification for CycloneDX sample" digest_verify_cyclonedx

cat <<EOF

Smoke test completed.
Passed: ${CHECKS_PASSED}
Failed: ${CHECKS_FAILED}
Generated artifacts: ${OUT_DIR}

Note: digest verification is performed offline with securesbom-verifier. Set
SECURESBOM_VERIFIER_DIR or SECURESBOM_VERIFIER_BIN if the verifier is not
available at ../securesbom-verifier.
EOF

if (( CHECKS_FAILED > 0 )); then
	printf '\nFailed checks:\n' >&2
	printf '  - %s\n' "${FAILED_CHECKS[@]}" >&2
fi
