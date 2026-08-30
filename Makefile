GO      ?= go
BIN     := bin
LDFLAGS := -s -w

# Cross-compilation target for `make dist`. A NAS is usually linux/amd64;
# set GOARCH=arm64 for an ARM one.
DIST_OS   ?= linux
DIST_ARCH ?= amd64
DIST      := dist/$(DIST_OS)-$(DIST_ARCH)

.PHONY: all build test vet check check-desktop clean dist desktop app images image-mock image-sangfor image-openconnect image-inode

all: build

build:
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN)/vpn-gateway-server ./cmd/vpn-gateway-server
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN)/vg-agent ./cmd/vg-agent
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN)/vgctl ./cmd/vgctl
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN)/vpn-gateway ./cmd/vpn-gateway

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

check: build vet test

# The desktop shell is excluded from the default build, so check it too where
# its libraries are present.
check-desktop:
	$(DESKTOP_ENV) $(GO) vet -tags desktop ./cmd/vpn-gateway-desktop
	$(DESKTOP_ENV) $(GO) test -tags desktop ./cmd/vpn-gateway-desktop

images: image-mock image-sangfor image-openconnect

# The iNode image needs H3C's installer, so it is not part of `make images`.
# Build it with: make image-inode INODE_INSTALLER=iNodeClient.tar.gz

image-mock:
	docker build -f images/mock/Dockerfile -t vpn-gateway/mock:dev .

image-sangfor:
	docker build -f images/sangfor/Dockerfile -t vpn-gateway/sangfor:dev .

image-openconnect:
	docker build -f images/openconnect/Dockerfile -t vpn-gateway/openconnect:dev .

image-inode:
	@test -n "$(INODE_INSTALLER)" || { echo "set INODE_INSTALLER to H3C's installer"; exit 1; }
	docker build -f images/inode/Dockerfile --build-arg INODE_INSTALLER=$(INODE_INSTALLER) -t vpn-gateway/inode:dev .

# The tray and window. It needs CGO and the platform's webview libraries, so
# it cannot be cross-compiled: build it on the machine that will run it. It is
# behind a build tag so a headless server still builds everything else.
#
#   Linux also needs: libgtk-3-dev libwebkit2gtk-4.1-dev
# Windows needs neither: the framework talks to WebView2 through pure Go, so
# `make desktop GOOS=windows` cross-compiles.
# The minimum macOS this is built for. Go defaults the link step to 10.13,
# older than the framework's Objective-C, which makes the linker warn on every
# object file; naming it on both the compile and link side settles that.
MACOS_MIN ?= 11.0
DESKTOP_ENV := MACOSX_DEPLOYMENT_TARGET=$(MACOS_MIN) \
	CGO_CFLAGS=-mmacosx-version-min=$(MACOS_MIN) \
	CGO_LDFLAGS=-mmacosx-version-min=$(MACOS_MIN)

desktop:
	$(DESKTOP_ENV) $(GO) build -tags desktop -trimpath -ldflags="$(LDFLAGS)" \
		-o $(BIN)/vpn-gateway-desktop ./cmd/vpn-gateway-desktop

# A macOS application bundle, so the shell can be launched from Finder and
# added to Login Items. Everything in it is generated: there is no icon file
# checked in, only the code that draws one.
# The bundle is a host artifact: the shell needs the platform's webview
# libraries and cannot be cross-compiled, so it does not belong under the
# cross-compilation directory.
APPDIR := dist/$(shell $(GO) env GOOS)-$(shell $(GO) env GOARCH)
APP    := $(APPDIR)/vpn-gateway.app

app: desktop
	@rm -rf "$(APP)" "$(APPDIR)/icon.iconset"
	@mkdir -p "$(APP)/Contents/MacOS" "$(APP)/Contents/Resources"
	cp packaging/macos/Info.plist "$(APP)/Contents/Info.plist"
	cp $(BIN)/vpn-gateway-desktop "$(APP)/Contents/MacOS/vpn-gateway-desktop"
	$(BIN)/vpn-gateway-desktop -write-iconset "$(APPDIR)/icon.iconset"
	iconutil -c icns "$(APPDIR)/icon.iconset" -o "$(APP)/Contents/Resources/icon.icns"
	@rm -rf "$(APPDIR)/icon.iconset"
	@echo "built $(APP)"
	@echo "unsigned, so the first launch needs right-click then Open"

# Binaries for the server, built for whatever the server runs. The images are
# built on the server itself, where the engine supplies the Go toolchain, so
# nothing but Docker has to be installed there.
dist:
	@mkdir -p $(DIST)
	GOOS=$(DIST_OS) GOARCH=$(DIST_ARCH) CGO_ENABLED=0 \
		$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/vpn-gateway-server ./cmd/vpn-gateway-server
	GOOS=$(DIST_OS) GOARCH=$(DIST_ARCH) CGO_ENABLED=0 \
		$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/vgctl ./cmd/vgctl
	GOOS=$(DIST_OS) GOARCH=$(DIST_ARCH) CGO_ENABLED=0 \
		$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/vpn-gateway ./cmd/vpn-gateway
	@echo "built for $(DIST_OS)/$(DIST_ARCH) in $(DIST)"

clean:
	rm -rf $(BIN) dist
