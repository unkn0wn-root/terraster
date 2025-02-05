package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	managerOnce sync.Once
	initErr     error
)

type Config struct {
	Level            string       `json:"level"`
	OutputPaths      []string     `json:"outputPaths"`
	ErrorOutputPaths []string     `json:"errorOutputPaths"`
	Development      bool         `json:"development"`
	LogToConsole     bool         `json:"logToConsole"`
	Sampling         Sampling     `json:"sampling"`
	Encoding         Encoding     `json:"encodingConfig"`
	LogRotation      LogRotation  `json:"logRotation"`
	Sanitization     Sanitization `json:"sanitization"`
}

type Sampling struct {
	Initial    int `json:"initial"`
	Thereafter int `json:"thereafter"`
}

type Encoding struct {
	TimeKey         string `json:"timeKey"`
	LevelKey        string `json:"levelKey"`
	NameKey         string `json:"nameKey"`
	CallerKey       string `json:"callerKey"`
	MessageKey      string `json:"messageKey"`
	StacktraceKey   string `json:"stacktraceKey"`
	LineEnding      string `json:"lineEnding"`
	LevelEncoder    string `json:"levelEncoder"`
	TimeEncoder     string `json:"timeEncoder"`
	DurationEncoder string `json:"durationEncoder"`
	CallerEncoder   string `json:"callerEncoder"`
}

type LogRotation struct {
	Enabled    bool `json:"enabled"`
	MaxSizeMB  int  `json:"maxSizeMB"`
	MaxBackups int  `json:"maxBackups"`
	MaxAgeDays int  `json:"maxAgeDays"`
	Compress   bool `json:"compress"`
}

// Sanitization configures sensitive field sanitization.
type Sanitization struct {
	SensitiveFields []string `json:"sensitiveFields"`
	Mask            string   `json:"mask"`
}

// Init initializes the loggers based on multiple configuration files.
// It should be called once at the start of the application.
func Init(configPaths []string, manager *LoggerManager) error {
	managerOnce.Do(func() {
		for _, configPath := range configPaths {
			var cfgMap map[string]Config
			data, err := os.ReadFile(configPath)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Printf("Configuration file '%s' not found. Skipping.\n", configPath)
					continue
				} else {
					initErr = fmt.Errorf("failed to read configuration file '%s': %w", configPath, err)
					return
				}
			}

			var configWrapper struct {
				Loggers map[string]Config `json:"loggers"`
			}
			if err := json.Unmarshal(data, &configWrapper); err != nil {
				initErr = fmt.Errorf("failed to parse configuration file '%s': %w", configPath, err)
				return
			}

			cfgMap = configWrapper.Loggers
			for name, cfg := range cfgMap {
				logger, err := buildLogger(name, &cfg)
				if err != nil {
					initErr = fmt.Errorf("failed to build logger '%s': %w", name, err)
					return
				}
				if err := manager.AddLogger(name, logger); err != nil {
					initErr = fmt.Errorf("failed to add logger '%s' from config '%s': %w", name, configPath, err)
					return
				}
			}
		}

		// If no loggers were loaded from config files, initialize default logger
		if len(manager.loggers) == 0 {
			defaultLogger, err := buildLogger("default", manager.defaultConfig)
			if err != nil {
				initErr = fmt.Errorf("failed to build default logger: %w", err)
				return
			}
			if err := manager.AddLogger("default", defaultLogger); err != nil {
				initErr = fmt.Errorf("failed to add default logger: %w", err)
				return
			}
		}
	})

	return initErr
}

func buildLogger(name string, cfg *Config) (*zap.Logger, error) {
	// Apply default configuration if any field is missing
	assignDefaultValues(cfg)

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        cfg.Encoding.TimeKey,
		LevelKey:       cfg.Encoding.LevelKey,
		NameKey:        cfg.Encoding.NameKey,
		CallerKey:      cfg.Encoding.CallerKey,
		MessageKey:     cfg.Encoding.MessageKey,
		StacktraceKey:  cfg.Encoding.StacktraceKey,
		LineEnding:     cfg.Encoding.LineEnding,
		EncodeLevel:    getZapLevelEncoder(cfg.Encoding.LevelEncoder),
		EncodeTime:     getZapTimeEncoder(cfg.Encoding.TimeEncoder),
		EncodeDuration: getZapDurationEncoder(cfg.Encoding.DurationEncoder),
		EncodeCaller:   getZapCallerEncoder(cfg.Encoding.CallerEncoder),
	}

	// Console Encoder with colored levels
	consoleEncoderConfig := encoderConfig
	consoleEncoderConfig.EncodeLevel = coloredLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(consoleEncoderConfig)

	jsonEncoder := zapcore.NewJSONEncoder(encoderConfig)
	atomicLevel := zap.NewAtomicLevelAt(getZapLevel(cfg.Level))

	var allCores []zapcore.Core
	if cfg.Development || cfg.LogToConsole {
		// 1. Console Core - Synchronous
		consoleWS := zapcore.Lock(os.Stdout)
		consoleCore := zapcore.NewCore(consoleEncoder, consoleWS, atomicLevel)
		allCores = append(allCores, consoleCore)
	}

	for _, path := range cfg.OutputPaths {
		if path == "stdout" || path == "stderr" {
			// Already handled by consoleCore
			continue
		}

		var fileWS zapcore.WriteSyncer
		if cfg.LogRotation.Enabled {
			lj := ljLogger(path, cfg.LogRotation)
			fileWS = zapcore.AddSync(lj)
		} else {
			file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return nil, fmt.Errorf("Failed to open log file '%s': %v\n", path, err)
			}
			fileWS = zapcore.AddSync(file)
		}

		fileCore := zapcore.NewCore(jsonEncoder, fileWS, atomicLevel)
		asyncFileCore := NewAsyncCore(fileCore, 1000, 100, 500*time.Millisecond) // bufferSize, batchSize, flushInterval
		allCores = append(allCores, asyncFileCore)
	}

	combinedCore := zapcore.NewTee(allCores...)

	// apply Sanitization if needed
	if len(cfg.Sanitization.SensitiveFields) > 0 {
		combinedCore = NewSanitizerCore(combinedCore, cfg.Sanitization.SensitiveFields, cfg.Sanitization.Mask)
	}

	logger := zap.New(combinedCore,
		zap.AddCaller(),
		zap.AddStacktrace(zap.ErrorLevel),
	).Named(name)

	return logger, nil
}

// maps string levels to zapcore.Level.
func getZapLevel(level string) zapcore.Level {
	switch strings.ToLower(level) {
	case "debug":
		return zap.DebugLevel
	case "info":
		return zap.InfoLevel
	case "warn", "warning":
		return zap.WarnLevel
	case "error":
		return zap.ErrorLevel
	case "dpanic":
		return zap.DPanicLevel
	case "panic":
		return zap.PanicLevel
	case "fatal":
		return zap.FatalLevel
	default:
		return zap.InfoLevel
	}
}

// maps string encoders to zapcore.LevelEncoder.
func getZapLevelEncoder(encoder string) zapcore.LevelEncoder {
	switch strings.ToLower(encoder) {
	case "lowercase":
		return zapcore.LowercaseLevelEncoder
	case "uppercase":
		return zapcore.CapitalLevelEncoder
	case "capital":
		return zapcore.CapitalLevelEncoder
	default:
		return zapcore.LowercaseLevelEncoder
	}
}

// maps string encoders to zapcore.TimeEncoder.
func getZapTimeEncoder(encoder string) zapcore.TimeEncoder {
	switch strings.ToLower(encoder) {
	case "iso8601":
		return zapcore.ISO8601TimeEncoder
	case "epoch":
		return zapcore.EpochTimeEncoder
	case "millis":
		return zapcore.EpochMillisTimeEncoder
	case "nanos":
		return zapcore.EpochNanosTimeEncoder
	default:
		return zapcore.ISO8601TimeEncoder
	}
}

// maps string encoders to zapcore.DurationEncoder.
func getZapDurationEncoder(encoder string) zapcore.DurationEncoder {
	switch strings.ToLower(encoder) {
	case "string":
		return zapcore.StringDurationEncoder
	case "seconds":
		return zapcore.SecondsDurationEncoder
	case "millis":
		return zapcore.MillisDurationEncoder
	case "nanos":
		return zapcore.NanosDurationEncoder
	default:
		return zapcore.StringDurationEncoder
	}
}

// maps string encoders to zapcore.CallerEncoder.
func getZapCallerEncoder(encoder string) zapcore.CallerEncoder {
	switch strings.ToLower(encoder) {
	case "full":
		return zapcore.FullCallerEncoder
	case "short":
		return zapcore.ShortCallerEncoder
	default:
		return zapcore.ShortCallerEncoder
	}
}

// adds color codes to log levels for console output - this is a bit slow so only in dev
func coloredLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	var level string
	switch l {
	case zapcore.DebugLevel:
		level = "\x1b[36m" + l.String() + "\x1b[0m" // Cyan
	case zapcore.InfoLevel:
		level = "\x1b[32m" + l.String() + "\x1b[0m" // Green
	case zapcore.WarnLevel:
		level = "\x1b[33m" + l.String() + "\x1b[0m" // Yellow
	case zapcore.ErrorLevel:
		level = "\x1b[31m" + l.String() + "\x1b[0m" // Red
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		level = "\x1b[35m" + l.String() + "\x1b[0m" // Magenta
	default:
		level = l.String()
	}
	enc.AppendString(level)
}

// creates a new Lumberjack logger with the given path and configuration.
func ljLogger(path string, l LogRotation) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   path,
		MaxSize:    l.MaxSizeMB,
		MaxBackups: l.MaxBackups,
		MaxAge:     l.MaxAgeDays,
		Compress:   l.Compress,
	}
}
