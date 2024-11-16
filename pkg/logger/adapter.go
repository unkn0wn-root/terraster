package logger

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// adapter implements io.Writer and writes to Zap logger.
type ZapWriter struct {
	logger *zap.Logger
	level  zapcore.Level
	prefix string
}

// - logger: the Zap structured logger.
// - level: the log level at which messages should be logged.
// - prefix: the prefix to include as a separate field (optional).
func NewZapWriter(logger *zap.Logger, level zapcore.Level, prefix string) *ZapWriter {
	return &ZapWriter{
		logger: logger,
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

	fields := []zap.Field{}

	if w.prefix != "" {
		fields = append(fields, zap.String("prefix", w.prefix))
	}

	switch w.level {
	case zapcore.DebugLevel:
		w.logger.Debug(msg, fields...)
	case zapcore.InfoLevel:
		w.logger.Info(msg, fields...)
	case zapcore.WarnLevel:
		w.logger.Warn(msg, fields...)
	case zapcore.ErrorLevel:
		w.logger.Error(msg, fields...)
	case zapcore.DPanicLevel:
		w.logger.DPanic(msg, fields...)
	case zapcore.PanicLevel:
		w.logger.Panic(msg, fields...)
	case zapcore.FatalLevel:
		w.logger.Fatal(msg, fields...)
	default:
		w.logger.Info(msg, fields...)
	}

	return len(p), nil
}
