SHELL := /bin/bash
.SHELLFLAGS := -eo pipefail -c
.DELETE_ON_ERROR:

MAP_FILE := ../cfmap.go

REGISTRY := core-parameters.xml
REGISTRY_URL := https://www.iana.org/assignments/core-parameters/$(REGISTRY)
REGISTRY_GO := core-parameters.go

EXE := main
CLEANFILES :=

zek ?= $(shell command -v zek)

all: $(MAP_FILE)

$(MAP_FILE): $(REGISTRY) $(EXE)
	./$(EXE) < $(REGISTRY) | gofmt > $@

$(EXE): $(REGISTRY_GO) ; go build

CLEANFILES += $(EXE)

$(REGISTRY_GO): $(REGISTRY)
	$(if $(strip $(zek)),,$(error zek not found. To install zek: 'go install github.com/miku/zek/cmd/zek@latest'))
	$(zek) -P main < $< > $@

CLEANFILES += $(REGISTRY_GO)

$(REGISTRY): ; curl -fsS -o $@ $(REGISTRY_URL)

CLEANFILES += $(REGISTRY)

clean: ; rm -f $(CLEANFILES) 
