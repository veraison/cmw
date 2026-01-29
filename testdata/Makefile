# Copyright 2023 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

DIAG_TESTDATA := $(wildcard *.diag)
CBOR_TESTDATA := $(DIAG_TESTDATA:.diag=.cbor)

.PHONY: all clean check-deps validate

# Default target with dependency checking
all: check-deps $(CBOR_TESTDATA)

# Check for required dependencies
check-deps:
	@echo "Checking dependencies..."
	@if ! command -v diag2cbor.rb >/dev/null 2>&1; then \
		echo "Error: diag2cbor.rb not found in PATH"; \
		echo "Please install the CBOR diagnostic tools."; \
		exit 1; \
	fi
	@echo "All dependencies found."

# Validate the build environment
validate: check-deps
	@echo "Validating testdata build environment..."
	@if [ -z "$(DIAG_TESTDATA)" ]; then \
		echo "Warning: No .diag files found to process."; \
	else \
		echo "Found $(words $(DIAG_TESTDATA)) .diag files to process."; \
	fi
	@echo "Build environment validated."

# Convert .diag files to .cbor with error checking
%.cbor: %.diag
	@echo "Converting $< to $@..."
	@if ! diag2cbor.rb $< > $@; then \
		echo "Error: Failed to convert $< to $@"; \
		rm -f $@; \
		exit 1; \
	fi
	@echo "Successfully converted $< to $@"

CLEANFILES += $(CBOR_TESTDATA)

clean:
	@echo "Cleaning generated CBOR files..."
	@$(RM) -f $(CLEANFILES)
	@echo "Clean completed."
