package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/trojan"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

var _ adapter.TCPInjectableInbound = (*DynamicTrojanInbound)(nil)

// DynamicTrojanInbound implements an inbound listener that validates Trojan connections
// dynamically against active user sessions.
type DynamicTrojanInbound struct {
	inbound.Adapter
	router    adapter.ConnectionRouterEx
	logger    log.ContextLogger
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	auth      Authenticator
}

// NewDynamicTrojanInbound creates an inbound adapter with dynamic authentication.
func NewDynamicTrojanInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrojanInboundOptions, auth Authenticator) (adapter.Inbound, error) {
	inboundAdapter := inbound.NewAdapter(C.TypeTrojan, tag)
	inb := &DynamicTrojanInbound{
		Adapter: inboundAdapter,
		router:  router,
		logger:  logger,
		auth:    auth,
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
			Context: ctx,
			Logger:  logger,
			Options: common.PtrValueOrDefault(options.TLS),
		})
		if err != nil {
			return nil, err
		}
		inb.tlsConfig = tlsConfig
	}
	inb.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inb,
	})
	return inb, nil
}

func (h *DynamicTrojanInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		if err := h.tlsConfig.Start(); err != nil {
			return err
		}
	}
	return h.listener.Start()
}

func (h *DynamicTrojanInbound) Close() error {
	return common.Close(
		h.listener,
		h.tlsConfig,
	)
}

func (h *DynamicTrojanInbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, "process connection from ", metadata.Source, ": TLS handshake: ", err)
			return
		}
		conn = tlsConn
	}
	if err := h.handleConnection(ctx, conn, metadata, onClose); err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, "process connection from ", metadata.Source, ": ", err)
	}
}

func (h *DynamicTrojanInbound) handleConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	var key [trojan.KeyLength]byte
	if _, err := io.ReadFull(conn, key[:]); err != nil {
		return err
	}

	authRes, ok := h.auth.ValidateTrojanKey(key)
	if !ok {
		return errors.New("unauthorized trojan credential or expired session")
	}

	if err := rw.SkipN(conn, 2); err != nil {
		return err
	}

	var command byte
	if err := binary.Read(conn, binary.BigEndian, &command); err != nil {
		return err
	}

	destination, err := M.SocksaddrSerializer.ReadAddrPort(conn)
	if err != nil {
		return err
	}

	if err := rw.SkipN(conn, 2); err != nil {
		return err
	}

	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.User = authRes.TunnelName
	metadata.Destination = destination

	untrack := h.auth.TrackConnection(authRes.Username, authRes.Token, conn)
	wrappedClose := func(it error) {
		untrack()
		if onClose != nil {
			onClose(it)
		}
	}

	h.logger.InfoContext(ctx, "[", authRes.TunnelName, "] connection for user [", authRes.Username, "] to ", destination)

	switch command {
	case trojan.CommandTCP:
		h.router.RouteConnectionEx(ctx, conn, metadata, wrappedClose)
	case trojan.CommandUDP:
		h.router.RoutePacketConnectionEx(ctx, &trojan.PacketConn{Conn: conn}, metadata, wrappedClose)
	default:
		return trojan.HandleMuxConnection(ctx, conn, metadata.Source, &dynamicMuxHandler{
			router:   h.router,
			metadata: metadata,
			onClose:  wrappedClose,
		}, h.logger, wrappedClose)
	}
	return nil
}

type dynamicMuxHandler struct {
	router   adapter.ConnectionRouterEx
	metadata adapter.InboundContext
	onClose  N.CloseHandlerFunc
}

func (h *dynamicMuxHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	meta := h.metadata
	meta.Source = source
	meta.Destination = destination
	h.router.RouteConnectionEx(ctx, conn, meta, onClose)
}

func (h *dynamicMuxHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	meta := h.metadata
	meta.Source = source
	meta.Destination = destination
	h.router.RoutePacketConnectionEx(ctx, conn, meta, onClose)
}
