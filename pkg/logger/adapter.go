package logger

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ZapWriter is an adapter that implements io.Writer and writes to Zap logger.
type ZapWriter struct {
	sugar  *zap.SugaredLogger
	level  zapcore.Level
	prefix string
}

// NewZapWriter creates a new ZapWriter.
// - sugar: the Zap sugared logger.
// - level: the log level at which messages should be logged.
// - prefix: the prefix to prepend to each log message.
func NewZapWriter(sugar *zap.SugaredLogger, level zapcore.Level, prefix string) *ZapWriter {
	return &ZapWriter{
		sugar:  sugar,
		level:  level,
		prefix: prefix,
	}
}

// Write implements the io.Writer interface.
func (w *ZapWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}

	// Prepend the prefix if any
	if w.prefix != "" {
		msg = w.prefix + " " + msg
	}

	// Log the message at the specified level
	switch w.level {
	case zapcore.DebugLevel:
		w.sugar.Debug(msg)
	case zapcore.InfoLevel:
		w.sugar.Info(msg)
	case zapcore.WarnLevel:
		w.sugar.Warn(msg)
	case zapcore.ErrorLevel:
		w.sugar.Error(msg)
	case zapcore.DPanicLevel:
		w.sugar.DPanic(msg)
	case zapcore.PanicLevel:
		w.sugar.Panic(msg)
	case zapcore.FatalLevel:
		w.sugar.Fatal(msg)
	default:
		w.sugar.Info(msg)
	}

	return len(p), nil
}
