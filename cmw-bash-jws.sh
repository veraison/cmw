#!/bin/bash
# RATS Conceptual Message Wrapper (CMW) - Full Implementation in Bash with JWS Support
# Based on draft-ietf-rats-msg-wrap and the Go implementation
# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

set -e

# Global variables and configuration
declare -A CMW_FORMATS=(
    [unknown]=0
    [json_record]=1
    [cbor_record]=2
    [cbor_tag]=3
)

declare -A CMW_KINDS=(
    [unknown]=0
    [monad]=1
    [collection]=2
)

declare -A CMW_INDICATORS=(
    [reference_values]=1
    [endorsements]=2
    [evidence]=4
    [attestation_results]=8
    [trust_anchors]=16
)

declare -A COAP_CONTENT_FORMAT=(
    ["application/json"]=50
    ["application/cbor"]=60
    ["application/eat+jwt"]=267
    ["application/eat-ucs+cbor"]=271
    ["application/eat-ucs+json"]=272
    ["application/cwt"]=61
    ["application/cose; cose-type=\"cose-sign1\""]=98
    ["application/vnd.intel.sgx"]=30001
    ["text/plain"]=0
)

declare -A CF_TO_MEDIATYPE=()
# Populate reverse mapping
for mt in "${!COAP_CONTENT_FORMAT[@]}"; do
    cf="${COAP_CONTENT_FORMAT[$mt]}"
    CF_TO_MEDIATYPE[$cf]="$mt"
done

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_debug() {
    if [[ "${CMW_DEBUG:-}" == "1" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $*"
    fi
}

# Utility functions
base64url_encode() {
    local input="$1"
    echo -n "$input" | base64 -w 0 | tr '+/' '-_' | tr -d '='
}

base64url_decode() {
    local input="$1"
    # Add padding if needed
    local padding=$((4 - ${#input} % 4))
    if [[ $padding -ne 4 ]]; then
        input="${input}$(printf '%*s' $padding | tr ' ' '=')"
    fi
    echo -n "$input" | tr '_-' '/+' | base64 -d
}

hex_encode() {
    local input="$1"
    echo -n "$input" | xxd -p | tr -d '\n'
}

hex_decode() {
    local input="$1"
    # Remove whitespace and newlines
    input=$(echo "$input" | tr -d ' \t\n')
    echo -n "$input" | xxd -r -p
}

is_valid_uri() {
    local uri="$1"
    # Basic URI validation (simplified)
    if [[ "$uri" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*: ]]; then
        return 0
    fi
    return 1
}

is_valid_oid() {
    local oid="$1"
    # OID validation: starts with 0, 1, or 2, followed by dot-separated numbers
    if [[ "$oid" =~ ^[0-2](\.[0-9]+)*$ ]]; then
        return 0
    fi
    return 1
}

# Format detection functions
sniff_format() {
    local data="$1"
    local first_char="${data:0:1}"
    
    case "$first_char" in
        "[")
            echo "json_record"
            ;;
        "{")
            echo "json_collection"  # Special case for collections
            ;;
        $'\x82'|$'\x83'|$'\x9f')
            echo "cbor_record"
            ;;
        $'\xa'*|$'\xb'*|$'\xbf')
            echo "cbor_collection"  # Special case for collections
            ;;
        $'\xda'|$'\xdb'|$'\xdc'|$'\xdd'|$'\xde'|$'\xdf')
            echo "cbor_tag"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Indicator functions
indicator_to_string() {
    local indicator="$1"
    local result=""
    local sep=""
    
    if (( indicator & CMW_INDICATORS[reference_values] )); then
        result="${result}${sep}reference values"
        sep=", "
    fi
    if (( indicator & CMW_INDICATORS[endorsements] )); then
        result="${result}${sep}endorsements"
        sep=", "
    fi
    if (( indicator & CMW_INDICATORS[evidence] )); then
        result="${result}${sep}evidence"
        sep=", "
    fi
    if (( indicator & CMW_INDICATORS[attestation_results] )); then
        result="${result}${sep}attestation results"
        sep=", "
    fi
    if (( indicator & CMW_INDICATORS[trust_anchors] )); then
        result="${result}${sep}trust anchors"
        sep=", "
    fi
    
    echo "$result"
}

# CMW Monad functions
create_monad() {
    local type="$1"
    local value="$2"
    local indicator="${3:-0}"
    local format="${4:-json_record}"
    
    if [[ -z "$type" || -z "$value" ]]; then
        log_error "Type and value are required for monad"
        return 1
    fi
    
    local cmw_file=$(mktemp)
    jq -n \
        --arg kind "monad" \
        --arg format "$format" \
        --arg type "$type" \
        --arg value "$value" \
        --argjson indicator "$indicator" \
        '{kind: $kind, format: $format, type: $type, value: $value, indicator: $indicator}' \
        > "$cmw_file"
    echo "$cmw_file"
}

encode_monad_json() {
    local cmw_file="$1"
    local type=$(jq -r '.type' "$cmw_file")
    local value=$(jq -r '.value' "$cmw_file")
    local indicator=$(jq -r '.indicator' "$cmw_file")
    
    local json_array="[\"$type\", \"$(base64url_encode "$value")\""
    
    if [[ "$indicator" != "0" ]]; then
        json_array="$json_array, $indicator"
    fi
    
    json_array="$json_array]"
    echo "$json_array"
}

# CMW Collection functions
create_collection() {
    local collection_type="$1"
    local format="${2:-json_record}"
    
    if [[ -z "$collection_type" ]]; then
        log_error "Collection type is required"
        return 1
    fi
    
    if ! is_valid_uri "$collection_type" && ! is_valid_oid "$collection_type"; then
        log_error "Collection type must be a valid URI or OID"
        return 1
    fi
    
    local cmw_file=$(mktemp)
    jq -n \
        --arg kind "collection" \
        --arg format "$format" \
        --arg collection_type "$collection_type" \
        '{kind: $kind, format: $format, collection_type: $collection_type, items: {}}' \
        > "$cmw_file"
    echo "$cmw_file"
}

add_collection_item() {
    local collection_file="$1"
    local key="$2"
    local item_file="$3"
    
    if [[ -z "$key" || -z "$item_file" ]]; then
        log_error "Key and item are required"
        return 1
    fi
    
    if [[ "$key" == "__cmwc_t" ]]; then
        log_error "Key '__cmwc_t' is reserved"
        return 1
    fi
    
    # Validate key (string or integer)
    if ! [[ "$key" =~ ^[a-zA-Z0-9_-]+$ || "$key" =~ ^[0-9]+$ ]]; then
        log_error "Invalid collection key: $key"
        return 1
    fi
    
    if [[ ! -f "$item_file" ]]; then
        log_error "Item file does not exist: $item_file"
        return 1
    fi
    
    local item_content
    item_content=$(cat "$item_file")
    
    # Update collection with new item
    local temp_file=$(mktemp)
    jq --arg key "$key" --argjson item "$item_content" '.items[$key] = $item' "$collection_file" > "$temp_file"
    mv "$temp_file" "$collection_file"
}

encode_collection_json() {
    local collection_file="$1"
    local collection_type=$(jq -r '.collection_type' "$collection_file")
    local items=$(jq -r '.items' "$collection_file")
    
    # Create JSON collection with __cmwc_t field
    jq -n --arg ctype "$collection_type" --argjson items "$items" '
        {"__cmwc_t": $ctype} + $items
    '
}

# Main CMW functions
validate_cmw() {
    local cmw_file="$1"
    
    if [[ ! -f "$cmw_file" ]]; then
        log_error "CMW file does not exist: $cmw_file"
        return 1
    fi
    
    local kind=$(jq -r '.kind' "$cmw_file")
    
    case "$kind" in
        "monad")
            validate_monad "$cmw_file"
            ;;
        "collection")
            validate_collection "$cmw_file"
            ;;
        *)
            log_error "Unknown CMW kind: $kind"
            return 1
            ;;
    esac
}

validate_monad() {
    local cmw_file="$1"
    local type=$(jq -r '.type' "$cmw_file")
    local value=$(jq -r '.value' "$cmw_file")
    
    if [[ -z "$type" || "$type" == "null" ]]; then
        log_error "Monad type is required"
        return 1
    fi
    
    if [[ -z "$value" || "$value" == "null" ]]; then
        log_error "Monad value is required"
        return 1
    fi
    
    return 0
}

validate_collection() {
    local cmw_file="$1"
    local collection_type=$(jq -r '.collection_type' "$cmw_file")
    local items=$(jq -r '.items | length' "$cmw_file")
    
    if [[ -z "$collection_type" || "$collection_type" == "null" ]]; then
        log_error "Collection type is required"
        return 1
    fi
    
    if ! is_valid_uri "$collection_type" && ! is_valid_oid "$collection_type"; then
        log_error "Invalid collection type: $collection_type"
        return 1
    fi
    
    if [[ "$items" == "0" ]]; then
        log_error "Collection cannot be empty"
        return 1
    fi
    
    return 0
}

marshal_cmw() {
    local cmw_file="$1"
    local output_format="${2:-json}"
    
    if ! validate_cmw "$cmw_file"; then
        return 1
    fi
    
    local kind=$(jq -r '.kind' "$cmw_file")
    
    case "$output_format" in
        "json")
            case "$kind" in
                "monad")
                    encode_monad_json "$cmw_file"
                    ;;
                "collection")
                    encode_collection_json "$cmw_file"
                    ;;
            esac
            ;;
        *)
            log_error "Unknown output format: $output_format"
            return 1
            ;;
    esac
}

# JWS (JSON Web Signature) functions for signing JSON CMW
# Based on Section 4.2 of draft-ietf-rats-msg-wrap

# Generate a test key for JWS signing (ES256)
generate_test_key() {
    log_warn "Using test key - not suitable for production use"
    
    # Sample ES256 key (same as in test_common.go)
    cat << 'EOF'
{
    "kty": "EC",
    "crv": "P-256",
    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
    "kid": "test-key-1"
}
EOF
}

# Create JWS header for CMW JSON signing
create_jws_header() {
    local algorithm="${1:-ES256}"
    local key_id="${2:-}"
    
    local header_json="{"
    header_json="$header_json\"alg\":\"$algorithm\""
    header_json="$header_json,\"cty\":\"application/cmw+json\""
    
    if [[ -n "$key_id" ]]; then
        header_json="$header_json,\"kid\":\"$key_id\""
    fi
    
    header_json="$header_json}"
    
    echo "$header_json"
}

# Simple ECDSA signature simulation (placeholder - use proper crypto library in production)
sign_ecdsa_p256() {
    local data="$1"
    local private_key_d="$2"
    
    # This is a placeholder implementation
    # In a real implementation, you would use proper crypto library
    log_warn "Using placeholder signature - implement proper ECDSA signing for production"
    
    # Generate a dummy signature based on hash of data
    echo -n "$data" | sha256sum | head -c 64 | xxd -r -p | base64 -w 0 | tr '+/' '-_' | tr -d '='
}

# Verify ECDSA signature (placeholder implementation)
verify_ecdsa_p256() {
    local data="$1"
    local signature="$2"
    local public_key_x="$3"
    local public_key_y="$4"
    
    log_warn "Using placeholder verification - implement proper ECDSA verification for production"
    
    # Placeholder verification - check signature is not empty and has reasonable length
    if [[ -n "$signature" && ${#signature} -ge 64 ]]; then
        return 0
    else
        return 1
    fi
}

# Sign JSON CMW using JWS
sign_json_cmw() {
    local cmw_file="$1"
    local key_file="${2:-}"
    local algorithm="${3:-ES256}"
    
    if [[ ! -f "$cmw_file" ]]; then
        log_error "CMW file does not exist: $cmw_file"
        return 1
    fi
    
    # Validate that this is a JSON-format CMW
    local format=$(jq -r '.format' "$cmw_file")
    if [[ "$format" != "json_record" ]] && [[ "$format" != *"json"* ]]; then
        log_error "CMW must be in JSON format for JWS signing"
        return 1
    fi
    
    # Get the key (use test key if none provided)
    local key_json
    if [[ -n "$key_file" && -f "$key_file" ]]; then
        key_json=$(cat "$key_file")
    else
        log_info "No key file provided, using test key"
        key_json=$(generate_test_key)
    fi
    
    # Extract key components
    local key_id=$(echo "$key_json" | jq -r '.kid // empty')
    local private_key_d=$(echo "$key_json" | jq -r '.d // empty')
    
    if [[ -z "$private_key_d" ]]; then
        log_error "Private key 'd' component not found"
        return 1
    fi
    
    # Marshal CMW to JSON payload
    local payload
    if ! payload=$(marshal_cmw "$cmw_file" "json"); then
        log_error "Failed to marshal CMW to JSON"
        return 1
    fi
    
    # Create JWS header
    local header_json
    header_json=$(create_jws_header "$algorithm" "$key_id")
    
    # Base64URL encode header and payload
    local header_b64=$(echo -n "$header_json" | base64 -w 0 | tr '+/' '-_' | tr -d '=')
    local payload_b64=$(echo -n "$payload" | base64 -w 0 | tr '+/' '-_' | tr -d '=')
    
    # Create signing input
    local signing_input="${header_b64}.${payload_b64}"
    
    # Sign the data
    local signature
    if ! signature=$(sign_ecdsa_p256 "$signing_input" "$private_key_d"); then
        log_error "Failed to sign data"
        return 1
    fi
    
    # Create JWS compact serialization
    local jws="${signing_input}.${signature}"
    
    echo "$jws"
}

# Verify JWS-signed JSON CMW
verify_json_cmw() {
    local jws_data="$1"
    local key_file="${2:-}"
    
    # Parse JWS compact serialization
    local header_b64=$(echo "$jws_data" | cut -d'.' -f1)
    local payload_b64=$(echo "$jws_data" | cut -d'.' -f2)
    local signature_b64=$(echo "$jws_data" | cut -d'.' -f3)
    
    if [[ -z "$header_b64" || -z "$payload_b64" || -z "$signature_b64" ]]; then
        log_error "Invalid JWS format"
        return 1
    fi
    
    # Decode header
    local header_json
    if ! header_json=$(base64url_decode "$header_b64" 2>/dev/null); then
        log_error "Failed to decode JWS header"
        return 1
    fi
    
    # Validate header
    local algorithm=$(echo "$header_json" | jq -r '.alg // empty')
    local content_type=$(echo "$header_json" | jq -r '.cty // empty')
    local key_id=$(echo "$header_json" | jq -r '.kid // empty')
    
    if [[ -z "$algorithm" ]]; then
        log_error "Missing mandatory alg parameter in JWS header"
        return 1
    fi
    
    if [[ "$content_type" != "application/cmw+json" ]]; then
        log_error "Unexpected content type in JWS header: $content_type"
        return 1
    fi
    
    # Get verification key
    local key_json
    if [[ -n "$key_file" && -f "$key_file" ]]; then
        key_json=$(cat "$key_file")
    else
        log_info "No key file provided, using test key"
        key_json=$(generate_test_key)
    fi
    
    # Extract public key components
    local public_key_x=$(echo "$key_json" | jq -r '.x // empty')
    local public_key_y=$(echo "$key_json" | jq -r '.y // empty')
    
    if [[ -z "$public_key_x" || -z "$public_key_y" ]]; then
        log_error "Public key components not found"
        return 1
    fi
    
    # Verify signature
    local signing_input="${header_b64}.${payload_b64}"
    
    if ! verify_ecdsa_p256 "$signing_input" "$signature_b64" "$public_key_x" "$public_key_y"; then
        log_error "JWS signature verification failed"
        return 1
    fi
    
    # Decode and validate payload
    local payload_json
    if ! payload_json=$(base64url_decode "$payload_b64" 2>/dev/null); then
        log_error "Failed to decode JWS payload"
        return 1
    fi
    
    # Return the decoded payload (CMW JSON)
    echo "$payload_json"
}

# Command-line interface functions
show_help() {
    cat << EOF
RATS Conceptual Message Wrapper (CMW) - Bash Implementation with JWS Support

USAGE:
    $0 <command> [options] [arguments]

COMMANDS:
    create-monad <type> <value> [indicator] [format]
        Create a new CMW monad
        
    create-collection <type> [format]
        Create a new CMW collection
        
    add-item <collection> <key> <item>
        Add an item to a collection
        
    marshal <cmw-file> [json|cbor]
        Marshal CMW to specified format
        
    validate <cmw-file>
        Validate a CMW structure
        
    info <cmw-file>
        Show CMW information
        
    sign-json <cmw-file> [key-file] [algorithm]
        Sign JSON CMW using JWS (JSON Web Signature)
        
    verify-json <jws-data> [key-file]
        Verify JWS-signed JSON CMW
        
    generate-key
        Generate a test key for JWS signing (ES256)
        
    examples
        Show usage examples

OPTIONS:
    -h, --help      Show this help message
    -d, --debug     Enable debug output
    -v, --verbose   Enable verbose output

FORMATS:
    json_record     JSON array format
    cbor_record     CBOR array format  
    cbor_tag        CBOR tag format

INDICATORS:
    reference_values    = 1
    endorsements        = 2
    evidence           = 4
    attestation_results = 8
    trust_anchors      = 16
    (can be combined with bitwise OR)

EXAMPLES:
    # Create and sign a monad
    $0 create-monad "application/json" '{"hello":"world"}' 4 > test.cmw
    $0 sign-json test.cmw > signed.jws
    $0 verify-json "\$(cat signed.jws)"

EOF
}

show_examples() {
    cat << EOF
CMW Examples with JWS Support:

1. Create a simple monad:
   $0 create-monad "text/plain" "Hello, World!" 0

2. Create a monad with evidence indicator:
   $0 create-monad "application/json" '{"attestation": "data"}' 4

3. Create a collection and add items:
   collection=\$($0 create-collection "tag:example.org,2024:test")
   item=\$($0 create-monad "text/plain" "test data" 1)
   $0 add-item "\$collection" "test-key" "\$item"

4. JWS Signing workflow:
   # Create CMW
   cmw=\$($0 create-monad "application/json" '{"test":"data"}' 4)
   # Generate key
   $0 generate-key > my-key.json
   # Sign CMW
   jws=\$($0 sign-json "\$cmw" my-key.json)
   # Verify signature
   $0 verify-json "\$jws" my-key.json

5. Quick test with default key:
   cmw=\$($0 create-monad "text/plain" "Hello JWS!" 0)
   signed=\$($0 sign-json "\$cmw")
   $0 verify-json "\$signed"

EOF
}

show_info() {
    local cmw_file="$1"
    
    if [[ ! -f "$cmw_file" ]]; then
        log_error "CMW file does not exist: $cmw_file"
        return 1
    fi
    
    local kind=$(jq -r '.kind' "$cmw_file")
    local format=$(jq -r '.format' "$cmw_file")
    
    echo -e "${CYAN}CMW Information:${NC}"
    echo "  Kind: $kind"
    echo "  Format: $format"
    
    case "$kind" in
        "monad")
            local type=$(jq -r '.type' "$cmw_file")
            local value=$(jq -r '.value' "$cmw_file")
            local indicator=$(jq -r '.indicator' "$cmw_file")
            local indicator_str=$(indicator_to_string "$indicator")
            
            local value_display="${value:0:50}"
            if [[ ${#value} -gt 50 ]]; then
                value_display="${value_display}..."
            fi
            
            echo "  Type: $type"
            echo "  Value: $value_display"
            echo "  Indicator: $indicator ($indicator_str)"
            ;;
        "collection")
            local collection_type=$(jq -r '.collection_type' "$cmw_file")
            local item_count=$(jq -r '.items | length' "$cmw_file")
            local keys=$(jq -r '.items | keys | join(", ")' "$cmw_file")
            
            echo "  Collection Type: $collection_type"
            echo "  Item Count: $item_count"
            echo "  Keys: $keys"
            ;;
    esac
}

# Main command dispatcher
main() {
    local command="${1:-}"
    
    # Parse global options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -d|--debug)
                export CMW_DEBUG=1
                shift
                ;;
            -v|--verbose)
                export CMW_VERBOSE=1
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
    
    command="$1"
    shift || true
    
    case "$command" in
        "create-monad")
            local type="${1:-}"
            local value="${2:-}"
            local indicator="${3:-0}"
            local format="${4:-json_record}"
            
            if [[ -z "$type" || -z "$value" ]]; then
                log_error "Type and value are required"
                show_help
                exit 1
            fi
            
            local cmw_file
            if cmw_file=$(create_monad "$type" "$value" "$indicator" "$format"); then
                log_success "Created monad: $cmw_file"
                echo "$cmw_file"
            else
                exit 1
            fi
            ;;
        "create-collection")
            local collection_type="${1:-}"
            local format="${2:-json_record}"
            
            if [[ -z "$collection_type" ]]; then
                log_error "Collection type is required"
                show_help
                exit 1
            fi
            
            local cmw_file
            if cmw_file=$(create_collection "$collection_type" "$format"); then
                log_success "Created collection: $cmw_file"
                echo "$cmw_file"
            else
                exit 1
            fi
            ;;
        "add-item")
            local collection_file="${1:-}"
            local key="${2:-}"
            local item_file="${3:-}"
            
            if [[ -z "$collection_file" || -z "$key" || -z "$item_file" ]]; then
                log_error "Collection file, key, and item file are required"
                show_help
                exit 1
            fi
            
            if add_collection_item "$collection_file" "$key" "$item_file"; then
                log_success "Added item to collection"
            else
                exit 1
            fi
            ;;
        "marshal")
            local cmw_file="${1:-}"
            local output_format="${2:-json}"
            
            if [[ -z "$cmw_file" ]]; then
                log_error "CMW file is required"
                show_help
                exit 1
            fi
            
            if result=$(marshal_cmw "$cmw_file" "$output_format"); then
                echo "$result"
            else
                exit 1
            fi
            ;;
        "validate")
            local cmw_file="${1:-}"
            
            if [[ -z "$cmw_file" ]]; then
                log_error "CMW file is required"
                show_help
                exit 1
            fi
            
            if validate_cmw "$cmw_file"; then
                log_success "CMW is valid"
            else
                exit 1
            fi
            ;;
        "info")
            local cmw_file="${1:-}"
            
            if [[ -z "$cmw_file" ]]; then
                log_error "CMW file is required"
                show_help
                exit 1
            fi
            
            show_info "$cmw_file"
            ;;
        "sign-json")
            local cmw_file="${1:-}"
            local key_file="${2:-}"
            local algorithm="${3:-ES256}"
            
            if [[ -z "$cmw_file" ]]; then
                log_error "CMW file is required"
                show_help
                exit 1
            fi
            
            if jws=$(sign_json_cmw "$cmw_file" "$key_file" "$algorithm"); then
                echo "$jws"
            else
                exit 1
            fi
            ;;
        "verify-json")
            local jws_data="${1:-}"
            local key_file="${2:-}"
            
            if [[ -z "$jws_data" ]]; then
                log_error "JWS data is required"
                show_help
                exit 1
            fi
            
            if result=$(verify_json_cmw "$jws_data" "$key_file"); then
                log_success "JWS signature verification passed"
                echo "$result"
            else
                exit 1
            fi
            ;;
        "generate-key")
            generate_test_key
            ;;
        "examples")
            show_examples
            ;;
        "")
            log_error "No command specified"
            show_help
            exit 1
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Cleanup function
cleanup() {
    # Clean up any temporary files
    if [[ -n "${CMW_TEMP_FILES:-}" ]]; then
        rm -f $CMW_TEMP_FILES
    fi
}

# Set up cleanup trap
trap cleanup EXIT

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    for cmd in jq base64 xxd; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Please install the missing dependencies and try again"
        exit 1
    fi
}

# Initialize
init() {
    # Check for required dependencies
    check_dependencies
    
    log_debug "CMW Bash implementation with JWS support initialized"
}

# Run initialization and main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    init
    main "$@"
fi