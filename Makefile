GO      ?= go
BIN     := bin
LDFLAGS := -s -w

.PHONY: all build test vet check clean images image-mock image-sangfor

all: build

build:
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN)/vpn-gateway-server ./cmd/vpn-gateway-server
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN)/vg-agent ./cmd/vg-agent
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN)/vgctl ./cmd/vgctl

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

check: build vet test

images: image-mock image-sangfor

image-mock:
	docker build -f images/mock/Dockerfile -t vpn-gateway/mock:dev .

image-sangfor:
	docker build -f images/sangfor/Dockerfile -t vpn-gateway/sangfor:dev .

clean:
	rm -rf $(BIN)
