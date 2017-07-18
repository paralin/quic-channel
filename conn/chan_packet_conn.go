package conn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/fuserobotics/quic-channel/packet"
)

// ChannelPacketConn wraps a send and receive channel as a net.PacketConn
type ChannelPacketConn struct {
	ctx       context.Context
	ctxCancel context.CancelFunc

	closeMtx      sync.Mutex
	closeCallback func(err error)
	closeErr      *error

	deadlineMtx   sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	localAddr  net.Addr
	remoteAddr net.Addr

	packetReadChan  <-chan *packet.RawPacket
	packetWriteChan chan<- *packet.RawPacket
}

// timeoutError is returned for any timeouts.
type timeoutError struct {
	error
	temp bool
}

// Timeout returns if this is a timeout or not.
func (c *timeoutError) Timeout() bool {
	return true
}

// Temporary returns if this is a temporary error or not.
func (c *timeoutError) Temporary() bool {
	return c.temp
}

// NewChannelPacketConn builds a ChannelPacketConn from the output channel.
func NewChannelPacketConn(
	ctx context.Context,
	closeCallback func(err error),
	packetReadChan <-chan *packet.RawPacket,
	packetWriteChan chan<- *packet.RawPacket,
	localAddr,
	remoteAddr net.Addr,
) *ChannelPacketConn {
	res := &ChannelPacketConn{
		closeCallback:   closeCallback,
		packetReadChan:  packetReadChan,
		packetWriteChan: packetWriteChan,
		localAddr:       localAddr,
		remoteAddr:      remoteAddr,
	}
	res.ctx, res.ctxCancel = context.WithCancel(ctx)
	return res
}

// GetContext returns the context for this connection.
func (c *ChannelPacketConn) GetContext() context.Context {
	return c.ctx
}

// contextCanceledMaybeClose returns the error to return when the context is closed.
func (c *ChannelPacketConn) contextCanceledMaybeClose() error {
	rerr := context.Canceled

	c.closeMtx.Lock()
	if c.closeErr == nil {
		go c.CloseWithError(rerr) // Spawn a goroutine because of our lock
	} else if (*c.closeErr) != nil {
		rerr = *c.closeErr
	}
	c.closeMtx.Unlock()

	return rerr
}

// LocalAddr returns the local network address.
func (c *ChannelPacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the remote network address.
func (c *ChannelPacketConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// ReadFrom reads a packet from the connection,
// copying the payload into b. It returns the number of
// bytes copied into b and the return address that
// was on the packet.
// ReadFrom can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetReadDeadline.
func (c *ChannelPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	for {
		c.deadlineMtx.Lock()
		readDeadline := c.readDeadline
		c.deadlineMtx.Unlock()

		// If there is no packet available, return.
		var deadline <-chan time.Time
		if !readDeadline.IsZero() {
			if readDeadline.Before(time.Now()) && !readDeadline.IsZero() {
				select {
				case pak := <-c.packetReadChan:
					if pak.Len() > len(b) {
						// panic(fmt.Sprintf("short buffer, %d > %d, data: %#v", pak.Len(), len(b), pak.Data().Bytes()))
						return 0, nil, io.ErrShortBuffer
					}
					copy(b, pak.Data().Bytes())
					return pak.Len(), c.remoteAddr, nil
				default:
				}

				return 0, nil, &timeoutError{error: errors.New("ReadFrom deadline exceeded.")}
			}

			// Otherwise, wait until then.
			deadline = time.After(time.Until(readDeadline))
		}

		select {
		case <-c.ctx.Done():
			return 0, nil, c.contextCanceledMaybeClose()
		case pak := <-c.packetReadChan:
			if pak.Len() > len(b) {
				// panic(fmt.Sprintf("short buffer, %d > %d, data: %#v", pak.Len(), len(b), pak.Data().Bytes()))
				return 0, nil, io.ErrShortBuffer
			}
			copy(b, pak.Data().Bytes())
			return pak.Len(), c.remoteAddr, nil
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
func (c *ChannelPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if addr != nil && addr != c.remoteAddr {
		return 0, fmt.Errorf("ChannelPacketConn) is bound to %s - cannot write to %s", c.remoteAddr.String(), addr.String())
	}

	outgoingBuf := &bytes.Buffer{}
	n, err = outgoingBuf.Write(b)
	if err != nil {
		return
	}
	outgoingPkt := packet.NewRawPacket(packet.PacketType(0), outgoingBuf)

	for {
		c.deadlineMtx.Lock()
		writeDeadline := c.writeDeadline
		c.deadlineMtx.Unlock()

		var deadline <-chan time.Time

		// If we cannot write immediately, return.
		if !writeDeadline.IsZero() {
			if writeDeadline.Before(time.Now()) {
				select {
				case c.packetWriteChan <- outgoingPkt:
					return outgoingBuf.Len(), nil
				default:
				}

				return 0, &timeoutError{error: errors.New("WriteFrom deadline exceeded.")}
			}

			// Otherwise, wait until then.
			deadline = time.After(time.Until(writeDeadline))
		}

		select {
		case <-c.ctx.Done():
			return 0, c.contextCanceledMaybeClose()
		case c.packetWriteChan <- outgoingPkt:
			return outgoingBuf.Len(), nil
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
func (c *ChannelPacketConn) SetDeadline(t time.Time) error {
	c.deadlineMtx.Lock()
	defer c.deadlineMtx.Unlock()

	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline sets the deadline for future ReadFrom calls
// and any currently-blocked ReadFrom call.
// A zero value for t means ReadFrom will not time out.
func (c *ChannelPacketConn) SetReadDeadline(t time.Time) error {
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
func (c *ChannelPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMtx.Lock()
	defer c.deadlineMtx.Unlock()

	c.writeDeadline = t
	return nil
}

// Close closes the channel.
// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
func (c *ChannelPacketConn) Close() error {
	return c.CloseWithError(nil)
}

// CloseWithError closes the ChannelPacketConn with an error.
func (c *ChannelPacketConn) CloseWithError(err error) error {
	c.closeMtx.Lock()
	defer c.closeMtx.Unlock()

	if c.closeErr != nil {
		return nil
	}

	c.closeErr = &err
	if c.closeCallback != nil {
		go c.closeCallback(err)
	}
	return nil
}
