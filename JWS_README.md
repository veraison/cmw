# CMW JWS (JSON Web Signature) Implementation

This directory contains a bash implementation of JWS (JSON Web Signature) signing for RATS Conceptual Message Wrapper (CMW) as specified in [draft-ietf-rats-msg-wrap](https://datatracker.ietf.org/doc/draft-ietf-rats-msg-wrap/) Section 4.2.

## Implementation Status

** Completed Features:**
- JWS header creation with proper algorithm (ES256) and content type
- CMW marshaling to JSON triple format `[type, value, indicator]`
- Base64URL encoding/decoding without padding
- JWS compact serialization format
- ES256 test key generation
- Comprehensive test suite (10 test cases)
- CLI commands for signing and verification

** Placeholder Components:**
- ECDSA signature generation (needs cryptographic library)
- ECDSA signature verification (needs cryptographic library)

## Files

### Core Implementation
- **`cmw-bash-jws.sh`** - Main bash script with JWS support for CMW
  - Create CMW monads and collections
  - Marshal CMW to JSON format
  - Sign JSON CMW with JWS
  - Generate ES256 test keys
  - Verify JWS signatures (placeholder)

### Testing
- **`test-cmw-jws.sh`** - Comprehensive test suite
  - 10 test cases covering all JWS functionality
  - Tests different CMW types and indicators
  - Validates JWS structure and compliance
  - Tests error handling and edge cases

### Demonstrations
- **`simple-jws-demo.sh`** - Simple end-to-end demo
  - Shows key generation, CMW creation, JWS signing
  - Demonstrates JWS structure inspection
  - Easy to understand workflow

- **`jws-comprehensive-demo.sh`** - Comprehensive demonstration
  - Multiple CMW types and indicators
  - Detailed JWS analysis and validation
  - Standards compliance verification

## Usage

### Basic JWS Signing
```bash
# Generate a test key
./cmw-bash-jws.sh generate-key > my-key.json

# Create a CMW monad
./cmw-bash-jws.sh create-monad "application/json" '{"data":"example"}' 4 json > evidence.cmw

# Sign with JWS
./cmw-bash-jws.sh sign-json evidence.cmw my-key.json > evidence.jws

# Verify JWS (placeholder)
./cmw-bash-jws.sh verify-json "$(cat evidence.jws)" my-key.json
```

### Run Tests
```bash
# Run comprehensive test suite
./test-cmw-jws.sh

# Run simple demonstration
./simple-jws-demo.sh
```

## Standards Compliance

### JWS (RFC 7515)
-  Compact serialization format
-  ES256 algorithm (ECDSA using P-256 and SHA-256)
-  Base64URL encoding without padding
-  Proper header structure with `alg`, `cty`, and `kid`
-  Content type `application/cmw+json`

### RATS CMW (draft-ietf-rats-msg-wrap)
-  Section 4.2 compliance for JSON CMW signing
-  CMW triple format: `[type, value, indicator]`
-  Proper indicator bit flags
-  JSON record format for signing
-  Base64 encoding for binary content

## JWS Structure

The implementation creates JWS in compact serialization format:
```
header.payload.signature
```

**Header** (Base64URL encoded):
```json
{
  "alg": "ES256",
  "cty": "application/cmw+json", 
  "kid": "test-key-1"
}
```

**Payload** (Base64URL encoded CMW triple):
```json
[
  "application/json",           // Content type
  "eyJkYXRhIjoiZXhhbXBsZSJ9",  // Base64 encoded content
  4                             // Indicator (evidence = 4)
]
```

**Signature** (Base64URL encoded ECDSA signature - placeholder)

## Next Steps for Production

1. **Implement Real ECDSA Signing**
   - Integrate with OpenSSL or similar cryptographic library
   - Replace placeholder signature generation
   
2. **Implement Real ECDSA Verification** 
   - Add proper public key validation
   - Replace placeholder verification logic
   
3. **Key Management**
   - Support for real key generation and storage
   - Integration with hardware security modules (HSMs)
   
4. **Additional Algorithms**
   - Support for RS256, PS256 algorithms
   - Algorithm negotiation based on key type

5. **Security Enhancements**
   - Key validation and certificate chains
   - Timestamp validation
   - Nonce handling for replay protection

## GitHub Issue Reference

This implementation addresses [GitHub Issue #15](https://github.com/veraison/cmw/issues/15) - "Implement JWS signing for JSON CMW" following the pattern from the CBOR signing implementation (PR #16).
