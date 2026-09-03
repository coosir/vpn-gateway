GO      ?= go
BIN     := bin
LDFLAGS := -s -w

# Cross-compilation target for `make dist`. A NAS is usually linux/amd64;
# set GOARCH=arm64 for an ARM one.
DIST_OS   ?= linux
DIST_ARCH ?= amd64
DIST      := dist/$(DIST_OS)-$(DIST_ARCH)

.PHONY: all build test vet check check-desktop clean dist desktop app images push builder image-inode

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

# --- binaries -------------------------------------------------------------

# Cross-compilation target for `make dist`. A NAS is usually linux/amd64;
# set DIST_ARCH=arm64 for an ARM one.
DIST_OS   ?= linux
DIST_ARCH ?= amd64
DIST      := dist/$(DIST_OS)-$(DIST_ARCH)

# The server's binaries, built for whatever the server runs. Pure Go, so they
# cross-compile from anywhere; the images are published separately and the
# server needs nothing else.
dist:
	@mkdir -p $(DIST)
	GOOS=$(DIST_OS) GOARCH=$(DIST_ARCH) CGO_ENABLED=0 \
		$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/vpn-gateway-server ./cmd/vpn-gateway-server
	GOOS=$(DIST_OS) GOARCH=$(DIST_ARCH) CGO_ENABLED=0 \
		$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/vgctl ./cmd/vgctl
	GOOS=$(DIST_OS) GOARCH=$(DIST_ARCH) CGO_ENABLED=0 \
		$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/vpn-gateway ./cmd/vpn-gateway
	@echo "built for $(DIST_OS)/$(DIST_ARCH) in $(DIST)"

# The minimum macOS the desktop shell is built for. Go defaults the link step
# to 10.13, older than the framework's Objective-C, which makes the linker warn
# on every object file; naming it on both sides settles that.
MACOS_MIN ?= 11.0
DESKTOP_ENV := MACOSX_DEPLOYMENT_TARGET=$(MACOS_MIN) \
	CGO_CFLAGS=-mmacosx-version-min=$(MACOS_MIN) \
	CGO_LDFLAGS=-mmacosx-version-min=$(MACOS_MIN)

# The tray and window. On macOS and Linux this needs the platform's webview
# libraries and cannot be cross-compiled: build it on the machine that will
# run it. On Windows the bindings are pure Go, so GOOS=windows works from
# anywhere. It is behind a build tag so a headless server still builds
# everything else.
#
#   Linux also needs: libgtk-3-dev libwebkit2gtk-4.1-dev
desktop:
	$(DESKTOP_ENV) $(GO) build -tags desktop -trimpath -ldflags="$(LDFLAGS)" \
		-o $(BIN)/vpn-gateway-desktop ./cmd/vpn-gateway-desktop

# A macOS application bundle, so the shell can be launched from Finder and
# added to Login Items. Everything in it is generated, including the icon:
# there is no image checked in, only the code that draws one.
#
# The command line client goes in beside the shell. It is what the background
# service runs, and the application installs that service itself: a bundle that
# could not do so without something else already on the machine would be one
# where TUN mode depends on having built this repository.
#
# It is a host artifact, so it does not live under the cross-compilation
# directory.
APPDIR := dist/$(shell $(GO) env GOOS)-$(shell $(GO) env GOARCH)
APP    := $(APPDIR)/vpn-gateway.app

app: desktop
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN)/vpn-gateway ./cmd/vpn-gateway
	@rm -rf "$(APP)" "$(APPDIR)/icon.iconset"
	@mkdir -p "$(APP)/Contents/MacOS" "$(APP)/Contents/Resources"
	cp packaging/macos/Info.plist "$(APP)/Contents/Info.plist"
	cp $(BIN)/vpn-gateway-desktop "$(APP)/Contents/MacOS/vpn-gateway-desktop"
	cp $(BIN)/vpn-gateway "$(APP)/Contents/MacOS/vpn-gateway"
	$(BIN)/vpn-gateway-desktop -write-iconset "$(APPDIR)/icon.iconset"
	iconutil -c icns "$(APPDIR)/icon.iconset" -o "$(APP)/Contents/Resources/icon.icns"
	@rm -rf "$(APPDIR)/icon.iconset"
	@echo "built $(APP)"

# Build the Windows application and the client it installs as its service.
#
# What ships is one file. The service must not be the application -- it runs as
# SYSTEM, and a window is not something a service manager should be starting --
# so the client executable is built first and carried inside the application,
# compressed, to be written out when the service is installed. That is what the
# packed tag switches on; without it the application looks for the client
# beside itself instead, which is what a build tree and the macOS bundle have.
PACKED := internal/clientbin/client.bin

windows:
	@mkdir -p dist/windows-amd64
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		$(GO) build -trimpath -ldflags="$(LDFLAGS)" \
		-o dist/windows-amd64/vpn-gateway.exe ./cmd/vpn-gateway
	@set -e; \
	trap 'rm -f $(PACKED)' EXIT; \
	gzip -9 -c dist/windows-amd64/vpn-gateway.exe > $(PACKED); \
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		$(GO) build -tags "desktop packed" -trimpath -ldflags="$(LDFLAGS) -H=windowsgui" \
		-o dist/windows-amd64/vpn-gateway-desktop.exe ./cmd/vpn-gateway-desktop
	@echo "built dist/windows-amd64/vpn-gateway-desktop.exe (carries vpn-gateway.exe) and vpn-gateway.exe"

# --- images ---------------------------------------------------------------
#
# Images are built here and pushed to a registry; the server pulls them. It
# never builds anything, which is what lets it run somewhere that cannot reach
# the sources these are assembled from.
#
# REGISTRY is the prefix everything is published under. IMAGE_TAG moves with
# each release; a server pulls whatever the tag points at.
REGISTRY  ?= coosir/vg-
IMAGE_TAG ?= latest

# Both architectures, so the same tag works on an x86 server and an ARM one.
# Drop to one to halve the build time: PLATFORMS=linux/amd64
PLATFORMS ?= linux/amd64,linux/arm64

# Building for more than one platform needs a builder that is not the default
# one: the docker driver cannot do it. This creates a container-backed builder
# once and reuses it.
BUILDER ?= vpn-gateway

# The vendor tier is not published: its images are built from an installer
# that cannot be redistributed.
PUBLISHED := mock sangfor openconnect

# Build for this machine only and keep the result loadable, for trying an
# image out before publishing it. buildx cannot load a multi-platform result
# into the engine, so this one is deliberately single-platform.
images: $(addprefix image-,$(PUBLISHED))

image-%:
	docker buildx build --load \
		-f images/$*/Dockerfile \
		-t $(REGISTRY)$*:$(IMAGE_TAG) .

# Create the multi-platform builder if it is not there yet.
builder:
	@docker buildx inspect $(BUILDER) >/dev/null 2>&1 || \
		docker buildx create --name $(BUILDER) --driver docker-container >/dev/null
	@docker buildx inspect $(BUILDER) --bootstrap >/dev/null

# Build for every platform and publish. This is the one the server consumes.
push: builder $(addprefix push-,$(PUBLISHED))
	@echo
	@echo "published:"
	@$(foreach n,$(PUBLISHED),echo "  $(REGISTRY)$(n):$(IMAGE_TAG)";)

push-%: builder
	docker buildx build --push --builder $(BUILDER) \
		--platform $(PLATFORMS) \
		-f images/$*/Dockerfile \
		-t $(REGISTRY)$*:$(IMAGE_TAG) .

# H3C's installer is not redistributable, so this image is built from your own
# copy and stays on machines you control:
#   make image-inode INODE_INSTALLER=iNodeClient.tar.gz
image-inode:
	@test -n "$(INODE_INSTALLER)" || { echo "set INODE_INSTALLER to H3C's installer"; exit 1; }
	docker buildx build --load \
		-f images/inode/Dockerfile \
		--build-arg INODE_INSTALLER=$(INODE_INSTALLER) \
		-t $(REGISTRY)inode:$(IMAGE_TAG) .

clean:
	rm -rf $(BIN) dist $(PACKED)
