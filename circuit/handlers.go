package circuit

import (
	"github.com/fuserobotics/quic-channel/session"
)

// StreamHandlerBuilders are stream handler builders for each stream type.
var StreamHandlerBuilders = map[session.StreamType]session.StreamHandlerBuilder{
	session.StreamType(EStreamType_STREAM_CONTROL): &controlStreamHandlerBuilder{},
	session.StreamType(EStreamType_STREAM_CIRCUIT): &circuitStreamHandlerBuilder{},
}
