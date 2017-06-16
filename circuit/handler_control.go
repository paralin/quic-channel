package circuit

import (
	"context"

	pkt "github.com/fuserobotics/quic-channel/packet"
	"github.com/fuserobotics/quic-channel/session"
)

// controlStreamHandlerBuilder builds control stream handlers.
type controlStreamHandlerBuilder struct{}

// BuildHandler constructs the control stream handler.
func (b *controlStreamHandlerBuilder) BuildHandler(config *session.StreamHandlerConfig) (session.StreamHandler, error) {
	return &controlStreamHandler{
		config: config,
	}, nil
}

// controlStreamHandler manages control stream messages.
type controlStreamHandler struct {
	config *session.StreamHandlerConfig
}

// Handle manages the control stream.
func (h *controlStreamHandler) Handle(ctx context.Context) error {
	config := h.config
	state := config.Session.GetOrPutData(1, func() interface{} {
		state := newSessionControlState(ctx, config)
		if !config.Session.IsInitiator() {
			state.initTimestamp = config.Session.GetStartTime()
		}
		config.Session.StartPump(state.handleControl)
		return state
	}).(*sessionControlState)

	state.activeHandlerMtx.Lock()
	state.activeHandler = h
	state.activeHandlerMtx.Unlock()

	defer func() {
		state.activeHandlerMtx.Lock()
		if state.activeHandler == h {
			state.activeHandler = nil
		}
		state.activeHandlerMtx.Unlock()
	}()

	for {
		packet, err := config.PacketRw.ReadPacket(
			pkt.PacketIdentifierFunc(PacketIdentifier.IdentifyPacket),
		)
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return context.Canceled
		case state.packets <- packet:
		}
	}
}

// StreamType returns the type of stream this handles.
func (h *controlStreamHandler) StreamType() session.StreamType {
	return session.StreamType(EStreamType_STREAM_CONTROL)
}
