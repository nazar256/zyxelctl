GO ?= go
PREFIX ?= $(HOME)/.local
DESTDIR ?=
BINDIR := $(DESTDIR)$(PREFIX)/bin
BUILD_DIR := build
BINARY := $(BUILD_DIR)/zyxelctl

.PHONY: all build test vet install uninstall clean help

all: build

build:
	mkdir -p "$(BUILD_DIR)"
	$(GO) build -o "$(BINARY)" ./cmd/zyxelctl

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

install: build
	install -d -m 0755 "$(BINDIR)"
	install -m 0755 "$(BINARY)" "$(BINDIR)/zyxelctl"
	install -m 0755 setup-iot-guest.sh "$(BINDIR)/setup-iot-guest"

uninstall:
	rm -f -- "$(BINDIR)/zyxelctl" "$(BINDIR)/setup-iot-guest"

clean:
	rm -f -- "$(BINARY)"

help:
	@echo "zyxelctl targets: build test vet install uninstall clean"
	@echo "Install defaults to PREFIX=$(PREFIX); override PREFIX for another user location."
