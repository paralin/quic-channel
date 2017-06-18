package circuit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/fuserobotics/quic-channel/route"
)

// Circuit manages state for a multi-hop connection.
// It also implements net.PacketConn.
type Circuit struct {
	ctx        context.Context
	ctxCancel  context.CancelFunc
	localAddr  net.Addr
	remoteAddr net.Addr

	deadlineMtx    sync.Mutex
	readDeadline   time.Time
	writeDeadline  time.Time
	routeEstablish *route.RouteEstablish

	packetChan      chan []byte
	packetWriteChan chan<- []byte
}

// newCircuit builds the base circuit object.
func newCircuit(
	ctx context.Context,
	localAddr,
	remoteAddr net.Addr,
	packetWriteChan chan<- []byte,
	routeEstablish *route.RouteEstablish,
) *Circuit {
	c := &Circuit{
		localAddr:       localAddr,
		remoteAddr:      remoteAddr,
		packetChan:      make(chan []byte),
		packetWriteChan: packetWriteChan,
		routeEstablish:  routeEstablish,
	}
	c.ctx, c.ctxCancel = context.WithCancel(ctx)
	return c
}

// handlePacket handles a packet.
func (c *Circuit) handlePacket(packet []byte) error {
	select {
	case <-c.ctx.Done():
		return context.Canceled
	case c.packetChan <- packet:
		return nil
	}
}

// LocalAddr returns the local network address.
func (c *Circuit) LocalAddr() net.Addr {
	return c.localAddr
}

// ReadFrom reads a packet from the connection,
// copying the payload into b. It returns the number of
// bytes copied into b and the return address that
// was on the packet.
// ReadFrom can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetReadDeadline.
func (c *Circuit) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		c.deadlineMtx.Lock()
		readDeadline := c.readDeadline
		c.deadlineMtx.Unlock()

		// If there is no packet available, return.
		var deadline <-chan time.Time
		if !readDeadline.IsZero() {
			if readDeadline.Before(time.Now()) && !readDeadline.IsZero() {
				select {
				case pak := <-c.packetChan:
					if len(pak) > len(b) {
						return 0, nil, io.ErrShortBuffer
					}
					copy(b, pak)
					return len(pak), c.remoteAddr, nil
				default:
				}

				return 0, nil, &circuitTimeoutError{error: errors.New("ReadFrom deadline exceeded.")}
			}

			// Otherwise, wait until then.
			deadline = time.After(time.Until(readDeadline))
		}

		select {
		case <-c.ctx.Done():
			return 0, nil, context.Canceled
		case pak := <-c.packetChan:
			if len(pak) > len(b) {
				return 0, nil, io.ErrShortBuffer
			}
			copy(b, pak)
			return len(pak), c.remoteAddr, nil
		case <-deadline:
			continue
		}
	}
}

// WriteTo writes a packet with payload b to addr.
// WriteTo can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (c *Circuit) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if addr != c.remoteAddr {
		return 0, fmt.Errorf("Circuit is bound to %s - cannot write to %s", c.remoteAddr.String(), addr.String())
	}

	for {
		c.deadlineMtx.Lock()
		writeDeadline := c.writeDeadline
		c.deadlineMtx.Unlock()

		var deadline <-chan time.Time
		// If we cannot write immediately, return.
		if !writeDeadline.IsZero() {
			if writeDeadline.Before(time.Now()) && !writeDeadline.IsZero() {
				select {
				case c.packetWriteChan <- b:
					return len(b), nil
				default:
				}

				return 0, &circuitTimeoutError{error: errors.New("WriteFrom deadline exceeded.")}
			}

			// Otherwise, wait until then.
			deadline = time.After(time.Until(writeDeadline))
		}

		select {
		case <-c.ctx.Done():
			return 0, context.Canceled
		case c.packetWriteChan <- b:
			return len(b), nil
		case <-deadline:
			continue
		}
	}
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to ReadFrom or
// WriteTo. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful ReadFrom or WriteTo calls.
//
// A zero value for t means I/O operations will not time out.
func (c *Circuit) SetDeadline(t time.Time) error {
	c.deadlineMtx.Lock()
	defer c.deadlineMtx.Unlock()

	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline sets the deadline for future ReadFrom calls
// and any currently-blocked ReadFrom call.
// A zero value for t means ReadFrom will not time out.
func (c *Circuit) SetReadDeadline(t time.Time) error {
	c.deadlineMtx.Lock()
	defer c.deadlineMtx.Unlock()

	c.readDeadline = t
	return nil
}

// SetWriteDeadline sets the deadline for future WriteTo calls
// and any currently-blocked WriteTo call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means WriteTo will not time out.
func (c *Circuit) SetWriteDeadline(t time.Time) error {
	c.deadlineMtx.Lock()
	defer c.deadlineMtx.Unlock()

	c.writeDeadline = t
	return nil
}

// Close closes the channel.
// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
func (c *Circuit) Close() error {
	c.ctxCancel()
	return nil
}
