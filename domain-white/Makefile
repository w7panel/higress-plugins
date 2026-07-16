PLUGIN_NAME ?= w7-domain
BUILDER_REGISTRY ?= higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/
REGISTRY ?= higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/
GO_VERSION ?= 1.20.14
TINYGO_VERSION ?= 0.29.0
ORAS_VERSION ?= 1.0.0
HIGRESS_VERSION ?= 1.0.0-rc
USE_HIGRESS_TINYGO ?= false
BUILDER ?= $(BUILDER_REGISTRY)wasm-go-builder:go$(GO_VERSION)-tinygo$(TINYGO_VERSION)-oras$(ORAS_VERSION)
BUILD_TIME := $(shell date "+%Y%m%d-%H%M%S")
COMMIT_ID := $(shell git rev-parse --short HEAD 2>/dev/null)
IMAGE_TAG = $(if $(strip $(PLUGIN_VERSION)),$(PLUGIN_VERSION),$(BUILD_TIME)-$(COMMIT_ID))
IMG ?= $(REGISTRY)$(PLUGIN_NAME):$(IMAGE_TAG)
IMAGE_VERSION ?= 1.0.0
PROXY_IMAGE ?= zpk.w7.cc/public/higress-plugin-domain:go-$(IMAGE_VERSION)
GOPROXY := $(shell go env GOPROXY)
EXTRA_TAGS ?= proxy_wasm_version_0_2_100

UI_DIR ?= ui
UI_DIST_DIR ?= $(UI_DIR)/dist
UI_PACKAGE_NAME ?= frontend.zip
UI_PACKAGE = $(UI_DIST_DIR)/$(UI_PACKAGE_NAME)
NPM ?= npm

PLUGIN_BUILD_ARGS = \
	--build-arg PLUGIN_NAME=$(PLUGIN_NAME) \
	--build-arg BUILDER=$(BUILDER) \
	--build-arg GOPROXY=$(GOPROXY) \
	--build-arg EXTRA_TAGS=$(EXTRA_TAGS) \
	-t $(IMG)

.PHONY: build build-ui build-image publish builder local-build local-run local-all

build: build-ui
	docker compose down
	DOCKER_BUILDKIT=1 docker build $(PLUGIN_BUILD_ARGS) --output extensions/$(PLUGIN_NAME) .
	@printf '\noutput wasm file: extensions/%s/plugin.wasm\n' "$(PLUGIN_NAME)"
	docker build -t $(PROXY_IMAGE) -f Dockerfile-proxy .

build-ui:
	cd $(UI_DIR) && $(NPM) install && $(NPM) run build
	rm -f $(UI_PACKAGE)
	cd $(UI_DIST_DIR) && zip -qr $(UI_PACKAGE_NAME) . -x $(UI_PACKAGE_NAME)
	@printf '\noutput ui package: %s\n' "$(UI_PACKAGE)"

build-image:
	DOCKER_BUILDKIT=1 docker build $(PLUGIN_BUILD_ARGS) .
	@printf '\nimage: %s\n' "$(IMG)"

publish: build
	docker push $(PROXY_IMAGE)

# builder:
# To build a wasm-go-builder image.
# e.g.
#   REGISTRY=<your_docker_registry> make builder
# If you want to use Go/TinyGo/Oras with another version, please modify GO_VERSION/TINYGO_VERSION/ORAS_VERSION.
# After your wasm-go-builder image is built, you can use it to build plugin image.
# e.g.
#   PLUGIN_NAME=request-block BUILDER=<your-wasm-go-builder> make
builder:
	docker buildx build --no-cache \
			--platform linux/amd64,linux/arm64 \
			--build-arg BASE_IMAGE=docker.io/ubuntu \
			--build-arg GO_VERSION=$(GO_VERSION) \
			--build-arg TINYGO_VERSION=$(TINYGO_VERSION) \
			--build-arg ORAS_VERSION=$(ORAS_VERSION) \
			--build-arg HIGRESS_VERSION=$(HIGRESS_VERSION) \
			--build-arg USE_HIGRESS_TINYGO=$(USE_HIGRESS_TINYGO) \
			-f DockerfileBuilder \
			-t $(BUILDER) \
			--push \
			.
	@printf '\nimage: %s\n' "$(BUILDER)"

local-build:
	tinygo build -scheduler=none -target=wasi -gc=custom -tags='custommalloc nottinygc_finalizer' \
		-o extensions/$(PLUGIN_NAME)/main.wasm \
		extensions/$(PLUGIN_NAME)/main.go
	@printf '\nwasm: extensions/%s/main.wasm\n' "$(PLUGIN_NAME)"

local-run:
	python3 .devcontainer/gen_config.py $(PLUGIN_NAME)
	envoy -c extensions/$(PLUGIN_NAME)/config.yaml --concurrency 0 --log-level info --component-log-level wasm:debug

local-all: local-build local-run
