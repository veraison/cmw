#!/bin/bash

# Build system validation script for CMW project
# This script validates that all build dependencies and processes work correctly

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Script configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Validation functions
check_go_installation() {
    log_info "Checking Go installation..."
    if ! command -v go >/dev/null 2>&1; then
        log_error "Go is not installed or not in PATH"
        return 1
    fi
    
    local go_version
    go_version=$(go version)
    log_info "Found: $go_version"
    return 0
}

check_system_dependencies() {
    log_info "Checking system dependencies..."
    
    local missing_deps=()
    
    # Check for curl
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi
    
    # Check for make
    if ! command -v make >/dev/null 2>&1; then
        missing_deps+=("make")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing system dependencies: ${missing_deps[*]}"
        return 1
    fi
    
    log_info "All system dependencies found"
    return 0
}

validate_utils_makefile() {
    log_info "Validating utils Makefile..."
    
    cd "$PROJECT_ROOT/utils" || {
        log_error "Cannot access utils directory"
        return 1
    }
    
    # Check if we can install dependencies
    if ! make install-deps; then
        log_error "Failed to install utils dependencies"
        return 1
    fi
    
    # Validate the build environment
    if ! make validate; then
        log_error "Utils build environment validation failed"
        return 1
    fi
    
    # Test dry-run build
    if ! make --dry-run all; then
        log_error "Utils Makefile dry-run failed"
        return 1
    fi
    
    log_info "Utils Makefile validation passed"
    return 0
}

validate_testdata_makefile() {
    log_info "Validating testdata Makefile..."
    
    cd "$PROJECT_ROOT/testdata" || {
        log_error "Cannot access testdata directory"
        return 1
    }
    
    # Validate the build environment
    if make validate; then
        log_info "Testdata validation passed"
        
        # Test dry-run build if dependencies are available
        if make --dry-run all; then
            log_info "Testdata Makefile dry-run passed"
        else
            log_warn "Testdata Makefile dry-run failed (dependencies may be missing)"
        fi
    else
        log_warn "Testdata validation failed (missing diag2cbor.rb)"
        log_info "This is acceptable if CBOR tools are not installed"
    fi
    
    return 0
}

validate_go_tests() {
    log_info "Validating Go tests..."
    
    cd "$PROJECT_ROOT" || {
        log_error "Cannot access project root"
        return 1
    }
    
    # Check if tests compile
    if ! go test -c -o /dev/null ./...; then
        log_error "Go tests do not compile"
        return 1
    fi
    
    # Run short tests
    if ! go test -short ./...; then
        log_error "Go short tests failed"
        return 1
    fi
    
    log_info "Go tests validation passed"
    return 0
}

validate_workflows() {
    log_info "Validating GitHub workflows..."
    
    local workflow_dir="$PROJECT_ROOT/.github/workflows"
    
    if [[ ! -d "$workflow_dir" ]]; then
        log_error "GitHub workflows directory not found"
        return 1
    fi
    
    # Check workflow files exist and are readable
    local workflows=("ci.yml" "ci-go-cover.yml")
    for workflow in "${workflows[@]}"; do
        local workflow_path="$workflow_dir/$workflow"
        if [[ ! -f "$workflow_path" ]]; then
            log_error "Workflow file not found: $workflow"
            return 1
        fi
        
        if [[ ! -r "$workflow_path" ]]; then
            log_error "Workflow file not readable: $workflow"
            return 1
        fi
        
        log_info "Found workflow: $workflow"
    done
    
    log_info "GitHub workflows validation passed"
    return 0
}

# Main validation function
main() {
    log_info "Starting CMW build system validation..."
    
    local validation_errors=0
    
    # Run all validations
    check_go_installation || ((validation_errors++))
    check_system_dependencies || ((validation_errors++))
    validate_go_tests || ((validation_errors++))
    validate_workflows || ((validation_errors++))
    validate_utils_makefile || ((validation_errors++))
    validate_testdata_makefile || ((validation_errors++))
    
    # Report results
    echo
    if [[ $validation_errors -eq 0 ]]; then
        log_info "✅ All validations passed! Build system is healthy."
        return 0
    else
        log_error "❌ $validation_errors validation(s) failed. Please address the issues above."
        return 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi