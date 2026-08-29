# The mock image carries no VPN at all: it dials straight out and reports a
# synthetic network. It exists so the whole system can be tested end to end
# without anyone's corporate credentials.
#
# Build from the repository root:
#   docker build -f images/mock/Dockerfile -t vpn-gateway/mock:dev .

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY pkg ./pkg
COPY internal ./internal
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vg-agent ./cmd/vg-agent

FROM alpine:3.22
RUN adduser -D -u 10001 vpngw
COPY --from=build /out/vg-agent /usr/local/bin/vg-agent

LABEL io.vpn-gateway.contract="1" \
      io.vpn-gateway.provider="mock" \
      io.vpn-gateway.capabilities="tcp,routes,dns"

# The mock provider needs no privileges; running unprivileged here keeps the
# test path honest about what a native provider should require.
USER vpngw
EXPOSE 1080 1081
ENTRYPOINT ["/usr/local/bin/vg-agent"]
