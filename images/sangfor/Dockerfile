# Sangfor EasyConnect and aTrust, via zju-connect.
#
# One image serves both protocols; the tunnel's VG_PROVIDER selects between
# them (easyconnect or atrust).
#
# Build from the repository root:
#   docker build -f images/sangfor/Dockerfile -t vpn-gateway/sangfor:dev .
#
# ZJU_CONNECT_VERSION is pinned deliberately. Upstream tracks vendor server
# changes, so an unpinned build can start failing without any change here.
# Bump it only after verifying the new version against a real gateway.

FROM golang:1.26-alpine AS agent
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY pkg ./pkg
COPY internal ./internal
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/vg-agent ./cmd/vg-agent

FROM golang:1.26-alpine AS zju
ARG ZJU_CONNECT_VERSION=v1.3.1
# The upstream go.mod carries replace directives, so `go install pkg@version`
# refuses it; the source has to be built as its own main module.
RUN apk add --no-cache git \
 && git clone --depth 1 --branch "${ZJU_CONNECT_VERSION}" \
      https://github.com/mythologyli/zju-connect.git /src \
 && cd /src \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/zju-connect .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 vpngw
COPY --from=agent /out/vg-agent /usr/local/bin/vg-agent
COPY --from=zju /out/zju-connect /usr/local/bin/zju-connect

LABEL io.vpn-gateway.contract="1" \
      io.vpn-gateway.provider="easyconnect,atrust" \
      io.vpn-gateway.capabilities="tcp,routes,dns"

# zju-connect implements the protocol in userspace and serves a SOCKS5 proxy,
# so it needs neither NET_ADMIN nor /dev/net/tun in this mode.
USER vpngw
EXPOSE 1080 1081
ENTRYPOINT ["/usr/local/bin/vg-agent"]
