package pool

import "sync"

// BufferPool is a wrapper around sync.Pool that provides a pool of reusable byte slices.
// It is designed to minimize memory allocations by reusing buffers, which can significantly
// improve performance in high-throughput scenarios such as proxy servers or data processing pipelines.
type BufferPool struct {
	sync.Pool
}

// NewBufferPool initializes and returns a new instance of BufferPool.
// It sets up the underlying sync.Pool with a default byte slice size of 32KB.
// This size is chosen as a balance between memory usage and the ability to handle large requests efficiently.
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
// This method ensures that the application reuses memory buffers efficiently, reducing the overhead of frequent allocations.
func (b *BufferPool) Get() []byte {
	return b.Pool.Get().([]byte)
}

// Put returns a byte slice back to the BufferPool for reuse.
// By recycling buffers, the application can significantly reduce memory fragmentation and garbage collection pressure.
// It is crucial to ensure that the byte slice being returned is no longer in use to prevent data races or unexpected behavior.
func (b *BufferPool) Put(buf []byte) {
	b.Pool.Put(buf)
}
