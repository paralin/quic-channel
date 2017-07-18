package memory

import (
	"bytes"
)

// BufferArena is a shared buffer arena.
type BufferArena struct {
	bufCh chan *bytes.Buffer
}

// NewBufferArena creates an arena with a size.
func NewBufferArena(size int) *BufferArena {
	var ch chan *bytes.Buffer

	if size <= 0 {
		ch = make(chan *bytes.Buffer)
	} else {
		ch = make(chan *bytes.Buffer, size)
	}

	return &BufferArena{bufCh: ch}
}

// GetBuffer returns an available buffer or creates a new one.
func (b *BufferArena) GetBuffer() *bytes.Buffer {
	select {
	case buf := <-b.bufCh:
		return buf
	default:
		return &bytes.Buffer{}
	}
}

// PutBuffer relinquishes a buffer back to the arena.
func (b *BufferArena) PutBuffer(buf *bytes.Buffer) {
	buf.Reset()

	select {
	case b.bufCh <- buf:
	default:
		// drop the buf on the floor for the GC to cleanup :)
	}
}
