NPM ?= npm
VERSION ?=
export VERSION
WAF_IMAGE ?= ccr.ccs.tencentyun.com/afan-public/w7panel-waf
ZPK_NAME := w7panel-pluginwaf
UI_DIST_DIR ?= dist
UI_PACKAGE_NAME ?= frontend.zip
UI_PACKAGE = $(UI_DIST_DIR)/$(UI_PACKAGE_NAME)

.PHONY: build ui build-ui build-helm build-image push-image check-catalog push-zpk full check-version check-release publish clean local-test

local-test:
	$(NPM) run dev

check-version:
	@test -n "$(VERSION)" || { echo 'Set VERSION=x.y.z' >&2; exit 2; }

check-release: check-version
	@for tool in npm zpk zip; do command -v "$$tool" >/dev/null || { echo "Missing $$tool" >&2; exit 2; }; done
	@test -n "$${ZPK_IDC_PASSWORD:-}" || { echo 'Set ZPK_IDC_PASSWORD' >&2; exit 2; }

.NOTPARALLEL: full
full: check-release build-ui build-helm push-image push-zpk

build: build-ui

ui: build-ui

build-ui:
	$(NPM) install
	$(NPM) run build
	rm -f $(UI_PACKAGE)
	cd $(UI_DIST_DIR) && zip -qr $(UI_PACKAGE_NAME) . -x $(UI_PACKAGE_NAME)
	@printf '\noutput ui package: %s\n' "$(UI_PACKAGE)"

check-catalog:
	python3 generate_catalog.py --check

build-helm: check-version
	mkdir -p $(UI_DIST_DIR)
	helm package chart --version $(VERSION) --destination $(UI_DIST_DIR)

build-image: check-version check-catalog
	docker build -t $(WAF_IMAGE):$(VERSION) wasm

push-image: build-image
	docker push $(WAF_IMAGE):$(VERSION)

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
