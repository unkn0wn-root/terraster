package logger

import (
	"sync"

	"go.uber.org/zap/zapcore"
)

type LogEntry struct {
	Entry  zapcore.Entry
	Fields []zapcore.Field
}

type AsyncCore struct {
	core       zapcore.Core
	entryChan  chan LogEntry
	wg         sync.WaitGroup
	quit       chan struct{}
	bufferSize int
}

func NewAsyncCore(core zapcore.Core, bufferSize int) *AsyncCore {
	ac := &AsyncCore{
		core:       core,
		entryChan:  make(chan LogEntry, bufferSize),
		quit:       make(chan struct{}),
		bufferSize: bufferSize,
	}

	ac.wg.Add(1)
	go ac.processEntries()

	return ac
}

// listens to the entry channel and writes logs to the underlying core.
func (ac *AsyncCore) processEntries() {
	defer ac.wg.Done()
	for {
		select {
		case logEntry := <-ac.entryChan:
			ac.core.Write(logEntry.Entry, logEntry.Fields)
		case <-ac.quit:
			// Drain the channel before exiting
			for {
				select {
				case logEntry := <-ac.entryChan:
					ac.core.Write(logEntry.Entry, logEntry.Fields)
				default:
					return
				}
			}
		}
	}
}

func (ac *AsyncCore) Enabled(level zapcore.Level) bool {
	return ac.core.Enabled(level)
}

func (ac *AsyncCore) With(fields []zapcore.Field) zapcore.Core {
	return &AsyncCore{
		core:       ac.core.With(fields),
		entryChan:  ac.entryChan,
		quit:       ac.quit,
		bufferSize: ac.bufferSize,
	}
}

func (ac *AsyncCore) Check(entry zapcore.Entry, checkedEntry *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if ac.Enabled(entry.Level) {
		return checkedEntry.AddCore(entry, ac)
	}
	return checkedEntry
}

func (ac *AsyncCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	logEntry := LogEntry{
		Entry:  entry,
		Fields: fields,
	}
	select {
	case ac.entryChan <- logEntry:
		return nil
	default:
		// If the channel is full, drop the log to prevent blocking
		// @todo - dont drop the log, wait to be able to write again
		return nil
	}
}

func (ac *AsyncCore) Sync() error {
	close(ac.quit)
	ac.wg.Wait()
	return ac.core.Sync()
}
