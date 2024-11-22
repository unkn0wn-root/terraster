package pool

import "sync"

// BufferPool is a wrapper around sync.Pool that provides a pool of reusable byte slices.
type BufferPool struct {
	sync.Pool
}

// NewBufferPool initializes and returns a new instance of BufferPool.
// It sets up the underlying sync.Pool with a default byte slice size of 32KB.
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
// If the pool is empty, it allocates a new byte slice using the New function defined in NewBufferPool.
func (b *BufferPool) Get() []byte {
	return b.Pool.Get().([]byte)
}

// Put returns a byte slice back to the BufferPool for reuse.
// By recycling buffers, the application can significantly reduce memory fragmentation and garbage collection pressure.
func (b *BufferPool) Put(buf []byte) {
	b.Pool.Put(buf)
}
