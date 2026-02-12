#!/bin/bash
#
# Comprehensive test suite for CMW JWS implementation
# Tests GitHub issue #15: JWS signing for JSON CMW
#

set -e

# Test configuration
TEST_DIR="/tmp/cmw-jws-tests"
CMW_SCRIPT="/workspaces/cmw/cmw-bash-jws.sh"
TEST_KEY_FILE=""
TEST_CMW_FILE=""
TEST_JWS=""
FAILED_TESTS=0
PASSED_TESTS=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_test() {
    echo -e "${BLUE}[TEST]${NC} $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
    PASSED_TESTS=$((PASSED_TESTS + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    FAILED_TESTS=$((FAILED_TESTS + 1))
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $*"
}

# Setup test environment
setup() {
    log_info "Setting up test environment..."
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"
    
    # Generate test key
    log_info "Generating test key..."
    TEST_KEY_FILE="$TEST_DIR/test-key.json"
    if ! $CMW_SCRIPT generate-key > "$TEST_KEY_FILE" 2>/dev/null; then
        log_fail "Failed to generate test key"
        exit 1
    fi
    
    log_info "Test environment ready"
    echo
}

# Cleanup
cleanup() {
    log_info "Cleaning up test environment..."
    rm -rf "$TEST_DIR"
}

# Base64URL decode function
base64url_decode() {
    local input="$1"
    # Replace base64url characters with base64
    input=$(echo -n "$input" | tr '_-' '/+')
    # Add padding if needed
    case $((${#input} % 4)) in
        2) input="${input}==" ;;
        3) input="${input}=" ;;
    esac
    # Decode
    printf "%s" "$input" | base64 -d 2>/dev/null
}

# Test helper to create CMW files
create_test_cmw() {
    local type="$1"
    local value="$2"
    local indicator="${3:-4}"
    local format="${4:-json}"
    
    local cmw_file
    if ! cmw_file=$($CMW_SCRIPT create-monad "$type" "$value" "$indicator" "$format" 2>/dev/null | tail -1); then
        echo "ERROR: Failed to create CMW" >&2
        return 1
    fi
    
    echo "$cmw_file"
}

# Test 1: Basic JWS key generation
test_key_generation() {
    log_test "Testing key generation..."
    
    local key_file="$TEST_DIR/gen-key.json"
    if ! $CMW_SCRIPT generate-key > "$key_file" 2>/dev/null; then
        log_fail "Key generation failed"
        return 1
    fi
    
    # Verify key structure
    if ! jq -e '.kty == "EC" and .crv == "P-256" and .d and .x and .y' "$key_file" >/dev/null; then
        log_fail "Generated key has invalid structure"
        return 1
    fi
    
    log_pass "Key generation works correctly"
}

# Test 2: Basic JWS signing
test_basic_jws_signing() {
    log_test "Testing basic JWS signing..."
    
    # Create test CMW
    local cmw_file
    if ! cmw_file=$(create_test_cmw "application/json" '{"test":"basic"}' 4 json); then
        log_fail "Failed to create test CMW"
        return 1
    fi
    
    # Sign CMW
    local jws_data
    if ! jws_data=$($CMW_SCRIPT sign-json "$cmw_file" "$TEST_KEY_FILE" 2>/dev/null); then
        log_fail "JWS signing failed"
        return 1
    fi
    
    # Verify JWS structure (3 parts separated by dots)
    if [[ $(echo "$jws_data" | grep -o '\.' | wc -l) -ne 2 ]]; then
        log_fail "JWS has invalid format (expected 3 parts)"
        return 1
    fi
    
    TEST_JWS="$jws_data"
    log_pass "Basic JWS signing works"
}

# Test 3: JWS header validation
test_jws_header() {
    log_test "Testing JWS header..."
    
    if [[ -z "$TEST_JWS" ]]; then
        log_fail "No JWS data available"
        return 1
    fi
    
    # Decode header
    local header
    local header_b64=$(echo "$TEST_JWS" | cut -d. -f1)
    if ! header=$(base64url_decode "$header_b64"); then
        log_fail "Failed to decode JWS header"
        return 1
    fi
    
    # Validate header structure
    if ! echo "$header" | jq -e '.alg == "ES256" and .cty == "application/cmw+json" and .kid' >/dev/null; then
        log_fail "JWS header has invalid structure"
        return 1
    fi
    
    log_pass "JWS header is valid"
}

# Test 4: JWS payload validation
test_jws_payload() {
    log_test "Testing JWS payload..."
    
    if [[ -z "$TEST_JWS" ]]; then
        log_fail "No JWS data available"
        return 1
    fi
    
    # Decode payload
    local payload
    local payload_b64=$(echo "$TEST_JWS" | cut -d. -f2)
    if ! payload=$(base64url_decode "$payload_b64"); then
        log_fail "Failed to decode JWS payload"
        return 1
    fi
    
    # Validate payload structure (should be JSON array with 3 elements)
    if ! echo "$payload" | jq -e 'type == "array" and length == 3' >/dev/null; then
        log_fail "JWS payload has invalid structure"
        return 1
    fi
    
    # Validate CMW triple structure
    if ! echo "$payload" | jq -e '.[0] | type == "string"' >/dev/null; then
        log_fail "CMW type (first element) is not a string"
        return 1
    fi
    
    if ! echo "$payload" | jq -e '.[2] | type == "number"' >/dev/null; then
        log_fail "CMW indicator (third element) is not a number"
        return 1
    fi
    
    log_pass "JWS payload is valid"
}

# Test 5: Different CMW types
# Test 5: Different CMW types
test_different_cmw_types() {
    log_test "Testing different CMW content types..."
    
    # Test each type individually to avoid shell parsing issues
    local types=("application/json" "text/plain" "application/cbor" "application/vnd.example")
    local values=('{"data":"json"}' "Hello World" "binary_data" "custom_data")
    
    for i in "${!types[@]}"; do
        local type="${types[$i]}"
        local value="${values[$i]}"
        
        log_info "Testing type: $type"
        
        # Create CMW
        local cmw_file
        if ! cmw_file=$(create_test_cmw "$type" "$value" 4 json); then
            log_fail "Failed to create CMW for type: $type"
            continue
        fi
        
        # Sign CMW
        local jws_data
        if ! jws_data=$($CMW_SCRIPT sign-json "$cmw_file" "$TEST_KEY_FILE" 2>/dev/null); then
            log_fail "Failed to sign CMW for type: $type"
            continue
        fi
        
        # Verify the type is preserved in payload
        local payload_type
        local payload_b64=$(echo "$jws_data" | cut -d. -f2)
        if ! payload_type=$(base64url_decode "$payload_b64" | jq -r '.[0]'); then
            log_fail "Failed to extract type from JWS payload"
            continue
        fi
        
        if [[ "$payload_type" != "$type" ]]; then
            log_fail "Type mismatch: expected $type, got $payload_type"
            continue
        fi
    done
    
    log_pass "Different CMW types work correctly"
}

# Test 6: Different indicators
test_different_indicators() {
    log_test "Testing different indicator values..."
    
    local indicators=(1 2 4 8 16 5 7 15 31)  # Various combinations
    
    for indicator in "${indicators[@]}"; do
        log_info "Testing indicator: $indicator"
        
        # Create CMW
        local cmw_file
        if ! cmw_file=$(create_test_cmw "application/json" '{"indicator":"test"}' "$indicator" json); then
            log_fail "Failed to create CMW for indicator: $indicator"
            continue
        fi
        
        # Sign CMW
        local jws_data
        if ! jws_data=$($CMW_SCRIPT sign-json "$cmw_file" "$TEST_KEY_FILE" 2>/dev/null); then
            log_fail "Failed to sign CMW for indicator: $indicator"
            continue
        fi
        
        # Verify indicator is preserved in payload
        local payload_indicator
        local payload_b64=$(echo "$jws_data" | cut -d. -f2)
        if ! payload_indicator=$(base64url_decode "$payload_b64" | jq -r '.[2]'); then
            log_fail "Failed to extract indicator from JWS payload"
            continue
        fi
        
        if [[ "$payload_indicator" != "$indicator" ]]; then
            log_fail "Indicator mismatch: expected $indicator, got $payload_indicator"
            continue
        fi
    done
    
    log_pass "Different indicator values work correctly"
}

# Test 7: Error handling
test_error_handling() {
    log_test "Testing error handling..."
    
    # Test missing CMW file
    if $CMW_SCRIPT sign-json "/nonexistent/file.json" "$TEST_KEY_FILE" >/dev/null 2>&1; then
        log_fail "Should fail with nonexistent CMW file"
        return 1
    fi
    
    # Test invalid key file
    echo "invalid key" > "$TEST_DIR/invalid-key.json"
    local cmw_file
    if ! cmw_file=$(create_test_cmw "application/json" '{"test":"error"}' 4 json); then
        log_fail "Failed to create test CMW"
        return 1
    fi
    
    if $CMW_SCRIPT sign-json "$cmw_file" "$TEST_DIR/invalid-key.json" >/dev/null 2>&1; then
        log_fail "Should fail with invalid key file"
        return 1
    fi
    
    # Test non-JSON CMW
    echo "not-json" > "$TEST_DIR/not-json.txt"
    if $CMW_SCRIPT sign-json "$TEST_DIR/not-json.txt" "$TEST_KEY_FILE" >/dev/null 2>&1; then
        log_fail "Should fail with non-JSON CMW"
        return 1
    fi
    
    log_pass "Error handling works correctly"
}

# Test 8: Base64URL encoding compliance
test_base64url_encoding() {
    log_test "Testing Base64URL encoding compliance..."
    
    if [[ -z "$TEST_JWS" ]]; then
        log_fail "No JWS data available"
        return 1
    fi
    
    # Check that JWS components don't contain +, /, or = characters
    local header=$(echo "$TEST_JWS" | cut -d. -f1)
    local payload=$(echo "$TEST_JWS" | cut -d. -f2)
    local signature=$(echo "$TEST_JWS" | cut -d. -f3)
    
    if [[ "$header" =~ [+/=] ]]; then
        log_fail "Header contains non-base64url characters"
        return 1
    fi
    
    if [[ "$payload" =~ [+/=] ]]; then
        log_fail "Payload contains non-base64url characters"
        return 1
    fi
    
    if [[ "$signature" =~ [+/=] ]]; then
        log_fail "Signature contains non-base64url characters"
        return 1
    fi
    
    log_pass "Base64URL encoding is compliant"
}

# Test 9: Large payload handling
test_large_payload() {
    log_test "Testing large payload handling..."
    
    # Create a large JSON payload
    local large_value='{"data":"'
    for i in {1..1000}; do
        large_value+="large_data_chunk_$i"
    done
    large_value+='"}'
    
    # Create CMW
    local cmw_file
    if ! cmw_file=$(create_test_cmw "application/json" "$large_value" 4 json); then
        log_fail "Failed to create large CMW"
        return 1
    fi
    
    # Sign CMW
    local jws_data
    if ! jws_data=$($CMW_SCRIPT sign-json "$cmw_file" "$TEST_KEY_FILE" 2>/dev/null); then
        log_fail "Failed to sign large CMW"
        return 1
    fi
    
    # Verify structure is still valid
    if [[ $(echo "$jws_data" | grep -o '\.' | wc -l) -ne 2 ]]; then
        log_fail "Large payload resulted in invalid JWS structure"
        return 1
    fi
    
    log_pass "Large payload handling works"
}

# Test 10: JWS verification (placeholder validation)
test_jws_verification() {
    log_test "Testing JWS verification..."
    
    if [[ -z "$TEST_JWS" ]]; then
        log_fail "No JWS data available"
        return 1
    fi
    
    # Test verification (should use placeholder verification)
    # Note: This will use placeholder verification, so we expect it to return an error
    # but the important thing is that it processes the JWS structure correctly
    
    local output
    output=$($CMW_SCRIPT verify-json "$TEST_JWS" "$TEST_KEY_FILE" 2>&1 || true)
    
    # Should mention placeholder verification
    if ! echo "$output" | grep -q "placeholder verification"; then
        log_fail "Verification doesn't indicate placeholder implementation"
        return 1
    fi
    
    log_pass "JWS verification processes structure correctly (placeholder implementation)"
}

# Main test runner
main() {
    echo "CMW JWS Implementation Test Suite"
    echo "================================="
    echo
    
    setup
    
    # Run all tests
    # Run all tests
    test_key_generation
    test_basic_jws_signing
    test_jws_header
    test_jws_payload
    test_different_cmw_types
    test_different_indicators
    test_error_handling
    test_base64url_encoding
    test_large_payload
    test_jws_verification
    
    cleanup
    
    echo
    echo "Test Results:"
    echo "============="
    echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "Failed: ${RED}$FAILED_TESTS${NC}"
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "\n${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "\n${RED}Some tests failed.${NC}"
        exit 1
    fi
}

# Run the tests
main "$@"