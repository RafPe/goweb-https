# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/rafpe/goweb-https/server:latest

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# GOLANGCI_LINT_VERSION pins the linter so local runs and CI agree.
GOLANGCI_LINT_VERSION ?= v2.1.6

# CMD is the package that produces the server binary.
CMD ?= ./cmd/goweb-https

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run tests with the race detector.
	go test -race -cover ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter.
	$(GOLANGCI_LINT) run ./...

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes.
	$(GOLANGCI_LINT) run --fix ./...

.PHONY: lint-config
lint-config: golangci-lint ## Verify the golangci-lint configuration.
	$(GOLANGCI_LINT) config verify

.PHONY: certs
certs: ## Regenerate the self-signed demo certificates.
	go run ./hack/gencerts

.PHONY: certs-client
certs-client: ## Generate a client CA and client certificate for mTLS testing.
	go run ./hack/gencerts -client-ca

##@ Build

.PHONY: build
build: fmt vet ## Build the server binary.
	go build -o bin/server $(CMD)

.PHONY: run
run: fmt vet ## Run the server from your host.
	go run $(CMD)

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the server.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the server.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the image, to provide support for
# multiple architectures. (i.e. make docker-buildx IMG=myregistry/myimage:0.0.1).
# To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
PLATFORMS ?= linux/arm64,linux/amd64

# A per-invocation builder name. Combined with the ownership check below this
# guarantees the recipe can only ever remove a builder it created itself, so a
# pre-existing builder belonging to someone else is never destroyed.
BUILDX_BUILDER ?= goweb-buildx-$(shell echo $$$$)

.PHONY: docker-buildx
docker-buildx: ## Build and push a multi-architecture docker image.
	$(CONTAINER_TOOL) buildx create --name $(BUILDX_BUILDER) >/dev/null
	status=0; \
	$(CONTAINER_TOOL) buildx build --builder $(BUILDX_BUILDER) --push --platform=$(PLATFORMS) --tag ${IMG} . || status=$$?; \
	$(CONTAINER_TOOL) buildx rm $(BUILDX_BUILDER) >/dev/null 2>&1 || true; \
	exit $$status

##@ Dependencies

## Location to install tool dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Install golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	@test -x $(GOLANGCI_LINT) && $(GOLANGCI_LINT) --version | grep -q $(GOLANGCI_LINT_VERSION) || \
	GOBIN=$(LOCALBIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
