BINARY_NAME=aws-utils
VERSION?=0.0.1
BUILD_DIR=build

GOCMD=go

GOPATH  := $(shell $(GOCMD) env GOPATH)
AIRPATH := $(GOPATH)/bin/air
GREEN   := $(shell tput -Txterm setaf 2)
YELLOW  := $(shell tput -Txterm setaf 3)
WHITE   := $(shell tput -Txterm setaf 7)
RESET   := $(shell tput -Txterm sgr0)

.PHONY: all build vendor

all: help

vendor:
	$(GOCMD) mod vendor

build:
	mkdir -p $(BUILD_DIR)
	rm -rf $(BUILD_DIR)/*
	CGO_ENABLED=0 GO111MODULE=on $(GOCMD) build -mod vendor -o $(BUILD_DIR)/$(BINARY_NAME) .

help:
	@echo ''
	@echo 'Usage:'
	@echo '  ${YELLOW}make${RESET} ${GREEN}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@echo "  ${YELLOW}build     ${RESET} ${GREEN}Build your project and put the output binary in $(BUILD_DIR)/$(BINARY_NAME)${RESET}"
	@echo "  ${YELLOW}vendor    ${RESET} ${GREEN}Copy of all packages needed to support builds and tests in the vendor directory${RESET}"