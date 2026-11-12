NPM ?= npm
VERSION ?=
export VERSION
ZPK_NAME := w7panel-pluginwaf
UI_DIST_DIR ?= dist
UI_PACKAGE_NAME ?= frontend.zip
UI_PACKAGE = $(UI_DIST_DIR)/$(UI_PACKAGE_NAME)

.PHONY: build ui build-ui build-helm build-image push-zpk full check-version check-release publish clean

check-version:
	@test -n "$(VERSION)" || { echo 'Set VERSION=x.y.z' >&2; exit 2; }

check-release: check-version
	@for tool in npm zpk zip; do command -v "$$tool" >/dev/null || { echo "Missing $$tool" >&2; exit 2; }; done
	@test -n "$${ZPK_IDC_PASSWORD:-}" || { echo 'Set ZPK_IDC_PASSWORD' >&2; exit 2; }

.NOTPARALLEL: full
full: check-release build-ui build-helm build-image push-zpk

build: build-ui

ui: build-ui

build-ui:
	$(NPM) install
	$(NPM) run build
	rm -f $(UI_PACKAGE)
	cd $(UI_DIST_DIR) && zip -qr $(UI_PACKAGE_NAME) . -x $(UI_PACKAGE_NAME)
	@printf '\noutput ui package: %s\n' "$(UI_PACKAGE)"

build-helm:
	@echo 'No Helm chart to package'

build-image:
	@echo 'Using the existing Higress WAF image'

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
