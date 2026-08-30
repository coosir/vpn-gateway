GO      ?= go
BIN     := bin
LDFLAGS := -s -w

.PHONY: all build test vet check clean images image-mock image-sangfor image-openconnect image-inode

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

clean:
	rm -rf $(BIN)
