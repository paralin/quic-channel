package session

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// sessionControlState is the state for the session's control data.
type sessionControlState struct {
	mtx     sync.Mutex
	config  *StreamHandlerConfig
	packets chan Packet
}

// handleControl manages the control state of the session.
func (s *sessionControlState) handleControl() error {
	ctx := s.config.Session.context
	for {
		var packet Packet
		select {
		case <-ctx.Done():
			return context.Canceled
		case packet = <-s.packets:
		}

		fmt.Printf("Got control packet: %#v\n", packet)
	}
}

// controlStreamHandlerBuilder builds control stream handlers.
type controlStreamHandlerBuilder struct{}

// BuildHandler constructs the control stream handler.
func (b *controlStreamHandlerBuilder) BuildHandler(config *StreamHandlerConfig) (StreamHandler, error) {
	return &controlStreamHandler{
		config: config,
	}, nil
}

// controlStreamHandler manages control stream messages.
type controlStreamHandler struct {
	config *StreamHandlerConfig
}

// Handle manages the control stream.
func (h *controlStreamHandler) Handle(ctx context.Context) error {
	config := h.config
	state := config.Session.GetOrPutData(1, func() interface{} {
		state := &sessionControlState{
			config:  config,
			packets: make(chan Packet, 5),
		}
		config.Session.startPump(state.handleControl)
		return state
	}).(*sessionControlState)

	for {
		packet, err := config.PacketRw.ReadPacket(ControlPacketIdentifier.IdentifyPacket)
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

// SendSessionInit sends ControlSessionInit to finalize starting the session.
func (h *controlStreamHandler) SendSessionInit(timestamp time.Time) error {
	return h.config.PacketRw.WritePacket(&ControlSessionInit{
		Timestamp: uint64(timestamp.Unix()),
	})
}

// StreamType returns the type of stream this handles.
func (h *controlStreamHandler) StreamType() EStreamType {
	return EStreamType_STREAM_CONTROL
}
