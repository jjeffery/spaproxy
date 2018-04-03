.PHONY: install release

GO ?= go

install:
	$(GO) install .

release:
	$(GO) run ./tools/build/main.go $(RELEASE_FLAGS)