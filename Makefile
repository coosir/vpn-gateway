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
	rm -rf $(BIN) dist
