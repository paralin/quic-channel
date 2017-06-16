package channel

import (
	"errors"
	"net"
	"time"
)

// Channel is a QUIC connection with a peer over one or more circuits.
type Channel struct {
	localAddr  net.Addr
	remoteAddr net.Addr
}

// LocalAddr returns the local network address.
func (c *Channel) LocalAddr() net.Addr {
	return c.localAddr
}

// ReadFrom reads a packet from the connection,
// copying the payload into b. It returns the number of
// bytes copied into b and the return address that
// was on the packet.
// ReadFrom can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetReadDeadline.
func (c *Channel) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return 0, c.remoteAddr, nil
}

// WriteTo writes a packet with payload b to addr.
// WriteTo can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (c *Channel) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if addr != c.remoteAddr {
		return 0, errors.New("Cannot xmit to other addresses.")
	}

	// TODO
	return 0, nil
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
func (c *Channel) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the deadline for future ReadFrom calls
// and any currently-blocked ReadFrom call.
// A zero value for t means ReadFrom will not time out.
func (c *Channel) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the deadline for future WriteTo calls
// and any currently-blocked WriteTo call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means WriteTo will not time out.
func (c *Channel) SetWriteDeadline(t time.Time) error {
	return nil
}

// Close closes the channel.
// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
func (c *Channel) Close() error {
	// TODO
	return nil
}
