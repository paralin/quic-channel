package conn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// localAddr is the local address.
var localAddr net.Addr = &net.UDPAddr{
	IP:   net.ParseIP("192.168.1.2"),
	Port: 3000,
}

// remoteAddr is the remote address.
var remoteAddr net.Addr = &net.UDPAddr{
	IP:   net.ParseIP("192.168.1.3"),
	Port: 3000,
}

// buildTestChannels builds the connection for the tests below.
func buildTestChannels(
	ctx context.Context,
	closeCallback func(err error),
) (readCh, writeCh chan []byte, conn *ChannelPacketConn) {
	readCh = make(chan []byte)
	writeCh = make(chan []byte)

	conn = NewChannelPacketConn(
		ctx,
		closeCallback,
		readCh,
		writeCh,
		localAddr,
		remoteAddr,
	)

	return
}

// waitForFunc waits for a func to exit and writes to an error channel.
func waitForFunc(f func() error) <-chan error {
	errCh := make(chan error)
	go func() {
		select {
		case errCh <- f():
		default:
		}
	}()
	return errCh
}

// expectToBlock asserts that the call blocks forever.
func expectToBlock(t *testing.T, f func() error) <-chan error {
	errCh := waitForFunc(f)

	select {
	case <-time.After(time.Duration(5) * time.Millisecond):
	case err := <-errCh:
		if err == nil {
			t.Fatal("Expected WriteTo without deadline and without reader to block.")
		} else {
			t.Fatal(err.Error())
		}
	}

	return errCh
}

// expectToNotBlock asserts that the call does not block.
func expectToNotBlock(t *testing.T, f func() error) error {
	errCh := waitForFunc(f)

	select {
	case <-time.After(time.Duration(5) * time.Millisecond):
		err := errors.New("expected to not block, but blocked")
		t.Fatal(err.Error())
		return err
	case err := <-errCh:
		return err
	}
}

// TestWriteWithoutDeadline tries to write without a deadline and without a receiver.
func TestWriteWithoutDeadline(t *testing.T) {
	testCtx, testCtxCancel := context.WithCancel(context.Background())
	defer testCtxCancel()

	_, _, conn := buildTestChannels(testCtx, nil)
	expectToBlock(t, func() error {
		_, err := conn.WriteTo([]byte{0x50, 0x49}, nil)
		return err
	})
}

// TestReadWithoutDeadline tries to read without a deadline and without a sender.
func TestReadWithoutDeadline(t *testing.T) {
	testCtx, testCtxCancel := context.WithCancel(context.Background())
	defer testCtxCancel()

	_, _, conn := buildTestChannels(testCtx, nil)
	expectToBlock(t, func() error {
		buf := make([]byte, 10)
		_, _, err := conn.ReadFrom(buf)
		return err
	})
}

// TestWriteWithDeadline tries to write with a deadline and a receiver.
func TestWriteWithDeadline(t *testing.T) {
	testCtx, testCtxCancel := context.WithCancel(context.Background())
	defer testCtxCancel()

	deadline := time.Now().Add(time.Duration(500) * time.Millisecond)
	_, _, conn := buildTestChannels(testCtx, nil)
	if err := expectToNotBlock(t, func() error {
		return conn.SetWriteDeadline(deadline)
	}); err != nil {
		t.Fatal(err.Error())
	}

	errCh := expectToBlock(t, func() error {
		_, err := conn.WriteTo([]byte{0x50, 0x49}, nil)
		return err
	})

	select {
	case <-time.After(time.Until(deadline) + (time.Duration(10) * time.Millisecond)):
		t.Fatal("Expected WriteTo to return a timeout after the deadline but never returned.")
	case err := <-errCh:
		if err == nil {
			t.Fatal("Expected WriteTo to return a timeout after the deadline but returned nil.")
		}
	}
}

// TestReadWithDeadline tries to read with a deadline and a receiver.
func TestReadWithDeadline(t *testing.T) {
	testCtx, testCtxCancel := context.WithCancel(context.Background())
	defer testCtxCancel()

	deadline := time.Now().Add(time.Duration(500) * time.Millisecond)
	_, _, conn := buildTestChannels(testCtx, nil)
	if err := expectToNotBlock(t, func() error {
		return conn.SetReadDeadline(deadline)
	}); err != nil {
		t.Fatal(err.Error())
	}

	errCh := expectToBlock(t, func() error {
		buf := make([]byte, 10)
		_, _, err := conn.ReadFrom(buf)
		return err
	})

	select {
	case <-time.After(time.Until(deadline) + (time.Duration(10) * time.Millisecond)):
		t.Fatal("Expected ReadFrom to return a timeout after the deadline but never returned.")
	case err := <-errCh:
		if err == nil {
			t.Fatal("Expected ReadFrom to return a timeout after the deadline but returned nil.")
		}
	}
}

// TestRead tries to read data.
func TestRead(t *testing.T) {
	testCtx, testCtxCancel := context.WithCancel(context.Background())
	defer testCtxCancel()

	deadline := time.Now().Add(time.Duration(500) * time.Millisecond)
	readCh, _, conn := buildTestChannels(testCtx, nil)
	if err := expectToNotBlock(t, func() error {
		return conn.SetReadDeadline(deadline)
	}); err != nil {
		t.Fatal(err.Error())
	}

	errCh := expectToBlock(t, func() error {
		buf := make([]byte, 10)
		_, _, err := conn.ReadFrom(buf)
		return err
	})

	readCh <- []byte{0x10}
	if err := <-errCh; err != nil {
		t.Fatal(err.Error())
	}
}
