package logger

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// SanitizerCore wraps a zapcore.Core and sanitizes log entries.
type SanitizerCore struct {
	zapcore.Core
	sensitiveFields []string
	mask            string
}

// NewSanitizerCore creates a new SanitizerCore.
func NewSanitizerCore(core zapcore.Core, sensitiveFields []string, mask string) *SanitizerCore {
	return &SanitizerCore{
		Core:            core,
		sensitiveFields: sensitiveFields,
		mask:            mask,
	}
}

// With adds structured context to the core.
func (s *SanitizerCore) With(fields []zapcore.Field) zapcore.Core {
	return &SanitizerCore{
		Core:            s.Core.With(fields),
		sensitiveFields: s.sensitiveFields,
		mask:            s.mask,
	}
}

// Check determines whether the supplied Entry should be logged.
func (s *SanitizerCore) Check(entry zapcore.Entry, checkedEntry *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if s.Enabled(entry.Level) {
		return checkedEntry.AddCore(entry, s)
	}
	return checkedEntry
}

// Write serializes the Entry and any Fields and writes them to the destination.
func (s *SanitizerCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	sanitizedFields := sanitizeFields(fields, s.sensitiveFields, s.mask)
	return s.Core.Write(entry, sanitizedFields)
}

// Sync flushes buffered logs (if any).
func (s *SanitizerCore) Sync() error {
	return s.Core.Sync()
}

// sanitizeFields processes fields and masks sensitive data.
func sanitizeFields(fields []zapcore.Field, sensitiveFields []string, mask string) []zapcore.Field {
	maskedFields := make([]zapcore.Field, len(fields))
	copy(maskedFields, fields)

	for i, field := range maskedFields {
		for _, sensitive := range sensitiveFields {
			if strings.EqualFold(field.Key, sensitive) {
				// Replace the value with the mask
				maskedFields[i] = zap.String(field.Key, mask)
				break
			}
		}
	}

	return maskedFields
}
