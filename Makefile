MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
.SUFFIXES:
.ONESHELL:

CONTAINER_TOOL=ko
TAG_COMMIT := $(shell git rev-list --abbrev-commit --tags --max-count=1)
TAG := $(shell git describe --abbrev=0 --tags ${TAG_COMMIT} 2>/dev/null || true)
COMMIT := $(shell git rev-parse --short HEAD)
DATE := $(shell git log -1 --format=%cd --date=format:"%Y%m%d")
VERSION := $(TAG:v%=%)

ifeq ($(VERSION),)
	VERSION := 0.0.0
endif

ifneq ($(COMMIT), $(TAG_COMMIT))
	VERSION := $(VERSION)-next-$(COMMIT)-$(DATE)
endif
ifeq ($(VERSION),)
	VERSION := $(COMMIT)-$(DATA)
endif
ifneq ($(shell git status --porcelain),)
	VERSION := $(VERSION)-dirty
endif

IMAGE_TAG := ${VERSION}
HELM_TAG := ${VERSION}

ifneq ($(IMAGE_TAG_FORCED),)
	IMAGE_TAG := ${IMAGE_TAG_FORCED}
endif
ifneq ($(HELM_TAG_FORCED),)
	HELM_TAG := ${HELM_TAG_FORCED}
endif


IMAGE_REGISTRY_NAMESPACE ?= angeloxx
IMAGE_TAG_BASE ?= $(IMAGE_REGISTRY_NAMESPACE)/cert-manager-essendi-issuer
IMAGE_REGISTRY ?= docker.io
BUNDLE_IMG ?= $(IMAGE_TAG_BASE)-bundle:v$(VERSION)
BUNDLE_GEN_FLAGS ?= -q --overwrite --version $(VERSION) $(BUNDLE_METADATA_OPTS)
IMAGE ?= $(IMAGE_REGISTRY)/$(IMAGE_TAG_BASE)
IMG_PUSH      ?= true
IMG_SBOM      ?= none

CURRENT_TAG_MICRO  := "v$(CURRENT_VERSION_MICRO)"
CURRENT_TAG_MINOR  := "v$(CURRENT_VERSION_MINOR)"
CURRENT_TAG_MAJOR  := "v$(CURRENT_VERSION_MAJOR)"

# cert-manager
CERT_MANAGER_VERSION ?= 1.11.1


INSTALL_YAML ?= build/install.yaml

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
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

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet ## Run tests
	go test ./... -coverprofile cover.out

##@ E2E testing

K8S_CLUSTER_NAME := essendi-xc-issuer-e2e

.PHONY: kind-cluster
kind-cluster: ## Use Kind to create a Kubernetes cluster for E2E tests
kind-cluster: kind
	 ${KIND} get clusters | grep ${K8S_CLUSTER_NAME} || ${KIND} create cluster --name ${K8S_CLUSTER_NAME}

.PHONY: kind-load
kind-load: kind ## Load all the Docker images into Kind
	${KIND} load docker-image --name ${K8S_CLUSTER_NAME} ${IMG}

.PHONY: kind-export-logs
kind-export-logs: kind ## Export Kind logs
	${KIND} export logs --name ${K8S_CLUSTER_NAME} ${E2E_ARTIFACTS_DIRECTORY}

.PHONY: deploy-cert-manager
deploy-cert-manager: ## Deploy cert-manager in the configured Kubernetes cluster in ~/.kube/config
	kubectl apply --filename=https://github.com/cert-manager/cert-manager/releases/download/v${CERT_MANAGER_VERSION}/cert-manager.yaml
	kubectl wait --for=condition=Available --timeout=300s apiservice v1.cert-manager.io

.PHONY: e2e
e2e: ## Run E2E tests
	kubectl apply --filename config/samples

	kubectl wait --for=condition=Ready --timeout=5s issuers.essendixc.angeloxx.ch issuer-sample
	kubectl wait --for=condition=Ready --timeout=5s  certificaterequests.cert-manager.io issuer-sample
	kubectl wait --for=condition=Ready --timeout=5s  certificates.cert-manager.io certificate-by-issuer

	kubectl wait --for=condition=Ready --timeout=5s clusterissuers.essendixc.angeloxx.ch clusterissuer-sample
	kubectl wait --for=condition=Ready --timeout=5s  certificaterequests.cert-manager.io clusterissuer-sample
	kubectl wait --for=condition=Ready --timeout=5s  certificates.cert-manager.io certificate-by-clusterissuer

	kubectl delete --filename config/samples

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary
	go build -o bin/manager main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./main.go

# If you wish built the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64 ). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: test ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}


PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: build-image
build-image: ko # vulncheck
	KO_DOCKER_REPO=${IMAGE} \
    ko build --tags ${IMAGE_TAG} --bare --sbom ${IMG_SBOM} \
      --image-label org.opencontainers.image.source="https://github.com/angeloxx/cert-manager-essendi-xc-issuer" \
      --image-label org.opencontainers.image.revision=$(shell git rev-parse HEAD) \
      --platform=${PLATFORMS}  --push=true .

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

# TODO(wallrj): .PHONY ensures that the install file is always regenerated,
# because I this really depends on the checksum of the Docker image and all the
# base Kustomize files.
.PHONY: ${INSTALL_YAML}
${INSTALL_YAML}: manifests kustomize
	mkdir -p $(dir $@)
	rm -rf build/kustomize
	mkdir -p build/kustomize
	cd build/kustomize
	$(KUSTOMIZE) create --resources ../../config/default
	$(KUSTOMIZE) edit set image controller=${IMG}
	cd ${CURDIR}
	$(KUSTOMIZE) build build/kustomize > $@

.PHONY: deploy
deploy: ${INSTALL_YAML}  ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	 kubectl apply -f ${INSTALL_YAML}

.PHONY: undeploy
undeploy: ${INSTALL_YAML} ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	 kubectl delete -f ${INSTALL_YAML}  --ignore-not-found=$(ignore-not-found)

##@ Build Dependencies

LOCAL_OS := $(shell go env GOOS)
LOCAL_ARCH := $(shell go env GOARCH)

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
KIND ?= $(LOCALBIN)/kind

## Tool Versions
KUSTOMIZE_VERSION ?= v3.8.7
CONTROLLER_TOOLS_VERSION ?= v0.11.3
KIND_VERSION := 0.18.0

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary. If wrong version is installed, it will be removed before downloading.
$(KUSTOMIZE): $(LOCALBIN)
	@if test -x $(LOCALBIN)/kustomize && ! $(LOCALBIN)/kustomize version | grep -q $(KUSTOMIZE_VERSION); then \
		echo "$(LOCALBIN)/kustomize version is not expected $(KUSTOMIZE_VERSION). Removing it before installing."; \
		rm -rf $(LOCALBIN)/kustomize; \
	fi
	test -s $(LOCALBIN)/kustomize || { curl -Ss $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN); }

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary. If wrong version is installed, it will be overwritten.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen && $(LOCALBIN)/controller-gen --version | grep -q $(CONTROLLER_TOOLS_VERSION) || \
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: kind
kind: $(LOCALBIN) ## Download Kind locally if necessary.
	curl -fsSL -o ${KIND} https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-${LOCAL_OS}-${LOCAL_ARCH}
	chmod +x ${KIND}

.PHONY: ko
ko:
	scripts/install-ko.sh

vulncheck:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

licenses:
	go install github.com/google/go-licenses@latest

build-licenses: licenses
	go-licenses report github.com/angeloxx/cert-manager-essendi-xc-issuer | tee LICENSES

check-licenses: licenses
	go-licenses check github.com/angeloxx/cert-manager-essendi-xc-issuer --allowed_licenses=Apache-2.0,BSD-3-Clause,BS2-3-Clause,BSD-2-Clause,ISC,MIT

helm:
	helm plugin install https://github.com/melmorabity/helm-kubeconform --version 0.6.4.1

.PHONY: build-helm
build-helm:
	sed -i.bak 's|tag: ".*"|tag: "$(VERSION)"|g' charts/cert-manager-essendi-issuer/values.yaml
	sed -i.bak 's|--version .*-helm|--version $(VERSION)-helm|g' README.md
	helm kubeconform --skip CustomResourceDefinition --summary charts/cert-manager-essendi-issuer
	helm package charts/cert-manager-essendi-issuer -d helm/charts --version $(VERSION)-helm
	helm repo index charts/charts --url https://angeloxx.github.io/cert-manager-essendi-issuer

.PHONY: build-helm-upload
build-helm-upload: build-helm
	helm push helm/charts/cert-manager-essendi-issuer-$(VERSION)-helm.tgz \
		oci://registry-1.docker.io/$(IMAGE_REGISTRY_NAMESPACE)