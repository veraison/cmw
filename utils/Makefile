MAP_FILE := ../cfmap.go

REGISTRY := core-parameters.xml
REGISTRY_URL := https://www.iana.org/assignments/core-parameters/$(REGISTRY)
REGISTRY_GO := core-parameters.go

EXE := main
CLEANFILES :=

# Check for zek availability with better error handling
zek ?= $(shell command -v zek 2>/dev/null)

.PHONY: all clean check-deps install-deps validate

# Default target with dependency checking
all: check-deps $(MAP_FILE)

# Check system dependencies
check-deps:
	@echo "Checking dependencies..."
	@if [ -z "$(zek)" ]; then \
		echo "Warning: zek not found. Run 'make install-deps' to install it."; \
		echo "Or install manually: go install github.com/miku/zek/cmd/zek@latest"; \
		exit 1; \
	fi
	@echo "All dependencies found."

# Install missing dependencies
install-deps:
	@echo "Installing zek dependency..."
	@if ! command -v go >/dev/null 2>&1; then \
		echo "Error: Go is required but not installed."; \
		exit 1; \
	fi
	@go install github.com/miku/zek/cmd/zek@latest
	@echo "Dependencies installed successfully."

# Validate the build environment
validate: check-deps
	@echo "Validating build environment..."
	@if [ ! -f "$(REGISTRY)" ] && ! curl --version >/dev/null 2>&1; then \
		echo "Error: curl is required to download registry but not found."; \
		exit 1; \
	fi
	@echo "Build environment validated."

$(MAP_FILE): $(REGISTRY) $(EXE)
	@echo "Generating content format map..."
	@if ! ./$(EXE) < $(REGISTRY) | gofmt > $@; then \
		echo "Error: Failed to generate $(MAP_FILE)"; \
		rm -f $@; \
		exit 1; \
	fi
	@echo "Generated $(MAP_FILE) successfully."

$(EXE): $(REGISTRY_GO)
	@echo "Building $(EXE)..."
	@if ! go build -o $(EXE); then \
		echo "Error: Failed to build $(EXE)"; \
		exit 1; \
	fi

CLEANFILES += $(EXE)

$(REGISTRY_GO): $(REGISTRY)
	@echo "Generating Go code from registry..."
	@if ! cat $< | $(zek) -P main > $@; then \
		echo "Error: Failed to generate $(REGISTRY_GO)"; \
		rm -f $@; \
		exit 1; \
	fi

CLEANFILES += $(REGISTRY_GO)

$(REGISTRY):
	@echo "Downloading registry..."
	@if ! curl -fsSL -o $@ $(REGISTRY_URL); then \
		echo "Error: Failed to download $(REGISTRY)"; \
		rm -f $@; \
		exit 1; \
	fi
	@echo "Downloaded $(REGISTRY) successfully."

CLEANFILES += $(REGISTRY)

clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(CLEANFILES)
	@echo "Clean completed." 