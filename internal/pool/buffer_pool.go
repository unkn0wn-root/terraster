package pool

import "sync"

type BufferPool struct {
	sync.Pool
}

func NewBufferPool() *BufferPool {
	return &BufferPool{
		Pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024) // 32KB default size
			},
		},
	}
}

func (b *BufferPool) Get() []byte {
	return b.Pool.Get().([]byte)
}

func (b *BufferPool) Put(buf []byte) {
	b.Pool.Put(buf)
}
