NPM ?= npm
UI_DIST_DIR ?= dist
UI_PACKAGE_NAME ?= frontend.zip
UI_PACKAGE = $(UI_DIST_DIR)/$(UI_PACKAGE_NAME)

.PHONY: build ui build-ui publish clean

build: ui

ui: build-ui publish

build-ui:
	$(NPM) install
	$(NPM) run build

publish:
	@if [ ! -d "$(UI_DIST_DIR)" ]; then \
		printf 'dist directory not found, building ui first...\n'; \
		$(MAKE) build-ui; \
	fi
	rm -f $(UI_PACKAGE)
	cd $(UI_DIST_DIR) && zip -qr $(UI_PACKAGE_NAME) . -x $(UI_PACKAGE_NAME)
	@printf '\noutput ui package: %s\n' "$(UI_PACKAGE)"

clean:
	rm -rf $(UI_DIST_DIR)
