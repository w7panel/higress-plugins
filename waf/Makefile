NPM ?= npm
VERSION ?=
export VERSION
WAF_IMAGE ?= ccr.ccs.tencentyun.com/afan-public/w7panel-waf
RUST_WAF_IMAGE ?= ccr.ccs.tencentyun.com/afan-public/w7panel-wafrust
ZPK_NAME := w7panel-pluginwaf
UI_DIR ?= ui
UI_DIST_DIR ?= $(UI_DIR)/dist
UI_PACKAGE_NAME ?= frontend.zip
UI_PACKAGE = $(UI_DIST_DIR)/$(UI_PACKAGE_NAME)

.PHONY: build ui build-ui build-helm build-image push-image build-rust-image push-rust-image check-catalog push-zpk full check-version check-release publish clean local-test

local-test:
	cd $(UI_DIR) && $(NPM) run dev

check-version:
	@test -n "$(VERSION)" || { echo 'Set VERSION=x.y.z' >&2; exit 2; }

check-release: check-version
	@for tool in npm zpk zip mise; do command -v "$$tool" >/dev/null || { echo "Missing $$tool" >&2; exit 2; }; done
	@mise exec rust@1.99.1 -- rustup target list --installed | grep -qx wasm32-wasip1 || { echo 'Install Rust target wasm32-wasip1 with mise' >&2; exit 2; }
	@test -n "$${ZPK_IDC_PASSWORD:-}" || { echo 'Set ZPK_IDC_PASSWORD' >&2; exit 2; }

.NOTPARALLEL: full
full: check-release build-ui build-helm push-image push-rust-image push-zpk

build: build-ui

ui: build-ui

build-ui:
	cd $(UI_DIR) && $(NPM) install && $(NPM) run build
	rm -f $(UI_PACKAGE)
	cd $(UI_DIST_DIR) && zip -qr $(UI_PACKAGE_NAME) . -x $(UI_PACKAGE_NAME)
	@printf '\noutput ui package: %s\n' "$(UI_PACKAGE)"

check-catalog:
	python3 $(UI_DIR)/scripts/generate_catalog.py --check

build-helm: check-version
	mkdir -p $(UI_DIST_DIR)
	helm package chart --version $(VERSION) --destination $(UI_DIST_DIR)

build-image: check-version check-catalog
	docker build -t $(WAF_IMAGE):$(VERSION) wasm

push-image: build-image
	docker push $(WAF_IMAGE):$(VERSION)

build-rust-image: check-version
	cd wasm-rust && mise exec rust@1.99.1 -- cargo build --locked --release --target wasm32-wasip1
	docker build -f wasm-rust/Dockerfile -t $(RUST_WAF_IMAGE):$(VERSION) wasm-rust/target/wasm32-wasip1/release

push-rust-image: build-rust-image
	docker push $(RUST_WAF_IMAGE):$(VERSION)

push-zpk: check-version
	@test -n "$${ZPK_IDC_PASSWORD:-}" || { echo 'Set ZPK_IDC_PASSWORD' >&2; exit 2; }
	@test -f "$(UI_PACKAGE)" || { echo "Missing $(UI_PACKAGE)" >&2; exit 1; }
	zpk login --username=admin --password="$${ZPK_IDC_PASSWORD}" --host=zpk.w7.cc
	zpk use --name=$(ZPK_NAME)
	zpk attach add --path="$(UI_PACKAGE)" --type=frontend
	zpk push

publish: build-ui

clean:
	rm -rf $(UI_DIST_DIR)
