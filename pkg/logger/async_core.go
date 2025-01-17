package logger

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap/zapcore"
)

type LogEntry struct {
	Entry  zapcore.Entry
	Fields []zapcore.Field
}

// wraps a zapcore.Core and handles asynchronous, batched logging.
type AsyncCore struct {
	core          zapcore.Core
	entryChan     chan LogEntry
	wg            sync.WaitGroup
	quit          chan struct{}
	bufferSize    int
	batchSize     int
	flushInterval time.Duration
	droppedLogs   uint64 // Atomic counter for dropped logs
	batchPool     *sync.Pool
}

// initializes a new AsyncCore with batching and tracking.
// bufferSize: size of the buffered channel
// batchSize: number of log entries per batch
// flushInterval: maximum time to wait before flushing a batch
func NewAsyncCore(core zapcore.Core, bufferSize, batchSize int, flushInterval time.Duration) *AsyncCore {
	if bufferSize <= 0 {
		bufferSize = 10000
	}
	if batchSize <= 0 || batchSize > bufferSize {
		batchSize = bufferSize / 10
	}
	if flushInterval <= 0 {
		flushInterval = time.Second
	}
	ac := &AsyncCore{
		core:          core,
		entryChan:     make(chan LogEntry, bufferSize),
		quit:          make(chan struct{}),
		bufferSize:    bufferSize,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		batchPool: &sync.Pool{
			New: func() interface{} {
				batch := make([]LogEntry, 0, batchSize)
				return &batch
			},
		},
	}

	ac.wg.Add(2)
	go ac.processEntries()
	go ac.monitorDroppedLogs()

	return ac
}

// listens to the entry channel and writes logs in batches.
func (ac *AsyncCore) processEntries() {
	defer ac.wg.Done()

	ticker := time.NewTicker(ac.flushInterval)
	defer ticker.Stop()

	batchPtr := ac.batchPool.Get().(*[]LogEntry)
	batch := *batchPtr
	batch = batch[:0]

	defer func() {
		if len(batch) > 0 {
			ac.writeBatch(batch)
		}
		*batchPtr = batch
		ac.batchPool.Put(batchPtr)
	}()

	for {
		select {
		case logEntry := <-ac.entryChan:
			batch = append(batch, logEntry)
			if len(batch) >= ac.batchSize {
				ac.writeBatch(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				ac.writeBatch(batch)
				batch = batch[:0]
			}
		case <-ac.quit:
			// Drain remaining log entries before exiting
			for {
				select {
				case logEntry := <-ac.entryChan:
					batch = append(batch, logEntry)
					if len(batch) >= ac.batchSize {
						ac.writeBatch(batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						ac.writeBatch(batch)
					}
					return
				}
			}
		}
	}
}

// writes a batch of log entries to the underlying core.
func (ac *AsyncCore) writeBatch(batch []LogEntry) {
	for _, logEntry := range batch {
		if err := ac.core.Write(logEntry.Entry, logEntry.Fields); err != nil {
			// should not happen but in case if we can't write to log - just print out to stdout
			fmt.Printf("Failed to write log entry: %v\n", err)
		}
	}
}

// periodically logs the number of dropped logs.
func (ac *AsyncCore) monitorDroppedLogs() {
	defer ac.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dropped := atomic.SwapUint64(&ac.droppedLogs, 0)
			if dropped > 0 {
				entry := zapcore.Entry{
					Level:      zapcore.WarnLevel,
					Message:    fmt.Sprintf("Dropped %d log entries due to full buffer", dropped),
					Time:       time.Now(),
					LoggerName: "AsyncCore",
				}
				ac.core.Write(entry, nil)
			}
		case <-ac.quit:
			return
		}
	}
}

func (ac *AsyncCore) Enabled(level zapcore.Level) bool {
	return ac.core.Enabled(level)
}

func (ac *AsyncCore) With(fields []zapcore.Field) zapcore.Core {
	return &AsyncCore{
		core:          ac.core.With(fields),
		entryChan:     ac.entryChan,
		quit:          ac.quit,
		bufferSize:    ac.bufferSize,
		batchSize:     ac.batchSize,
		flushInterval: ac.flushInterval,
	}
}

// enqueues the entry if enabled.
func (ac *AsyncCore) Check(entry zapcore.Entry, checkedEntry *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if ac.Enabled(entry.Level) {
		return checkedEntry.AddCore(entry, ac)
	}
	return checkedEntry
}

// enqueues the log entry along with its fields.
func (ac *AsyncCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	logEntry := LogEntry{
		Entry:  entry,
		Fields: fields,
	}
	select {
	case ac.entryChan <- logEntry:
		return nil
	default:
		// Increment the counter for dropped logs
		atomic.AddUint64(&ac.droppedLogs, 1)
		return nil
	}
}

// flushes all buffered log entries and syncs the underlying core.
func (ac *AsyncCore) Sync() error {
	close(ac.quit)
	ac.wg.Wait()
	return ac.core.Sync()
}
