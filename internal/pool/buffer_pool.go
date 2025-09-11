package pool

import "sync"

// BufferPool is a wrapper around sync.Pool that provides a pool of reusable byte slices.
type BufferPool struct {
	sync.Pool
}

// NewBufferPool initializes and returns a new instance of BufferPool.
func NewBufferPool() *BufferPool {
	return &BufferPool{
		Pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024) // 32KB default size
			},
		},
	}
}

// Get retrieves a byte slice from the BufferPool.
func (b *BufferPool) Get() []byte {
	return b.Pool.Get().([]byte)
}

// Put returns a byte slice back to the BufferPool for reuse.
func (b *BufferPool) Put(buf []byte) {
	b.Pool.Put(buf)
}
