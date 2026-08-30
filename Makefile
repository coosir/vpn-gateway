GO      ?= go
BIN     := bin
LDFLAGS := -s -w

# Cross-compilation target for `make dist`. A NAS is usually linux/amd64;
# set GOARCH=arm64 for an ARM one.
DIST_OS   ?= linux
DIST_ARCH ?= amd64
DIST      := dist/$(DIST_OS)-$(DIST_ARCH)

.PHONY: all build test vet check clean dist images image-mock image-sangfor image-openconnect image-inode

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
