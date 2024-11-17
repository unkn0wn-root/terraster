package logger

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	loggerInstance *zap.Logger
	once           sync.Once
)

type nopSyncWriter struct {
	io.Writer
}

func (w *nopSyncWriter) Sync() error {
	return nil
}

type Config struct {
	Level            string             `json:"level"`
	OutputPaths      []string           `json:"outputPaths"`
	ErrorOutputPaths []string           `json:"errorOutputPaths"`
	Development      bool               `json:"development"`
	Sampling         SamplingConfig     `json:"sampling"`
	EncodingConfig   EncodingConfig     `json:"encodingConfig"`
	LogRotation      LogRotationConfig  `json:"logRotation"`
	Sanitization     SanitizationConfig `json:"sanitization"`
}

type SamplingConfig struct {
	Initial    int `json:"initial"`
	Thereafter int `json:"thereafter"`
}

type EncodingConfig struct {
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

type LogRotationConfig struct {
	Enabled    bool `json:"enabled"`
	MaxSizeMB  int  `json:"maxSizeMB"`
	MaxBackups int  `json:"maxBackups"`
	MaxAgeDays int  `json:"maxAgeDays"`
	Compress   bool `json:"compress"`
}

type SanitizationConfig struct {
	SensitiveFields []string `json:"sensitiveFields"`
	Mask            string   `json:"mask"`
}

// defaultConfig provides fallback logging settings
var defaultConfig = Config{
	Level:       "info",
	OutputPaths: []string{"stdout"},
	ErrorOutputPaths: []string{
		"stderr",
	},
	Development: false,
	Sampling: SamplingConfig{
		Initial:    100,
		Thereafter: 100,
	},
	EncodingConfig: EncodingConfig{
		TimeKey:         "time",
		LevelKey:        "level",
		NameKey:         "logger",
		CallerKey:       "caller",
		MessageKey:      "msg",
		StacktraceKey:   "stacktrace",
		LineEnding:      "\n",
		LevelEncoder:    "lowercase",
		TimeEncoder:     "iso8601",
		DurationEncoder: "string",
		CallerEncoder:   "short",
	},
	LogRotation: LogRotationConfig{
		Enabled:    true,
		MaxSizeMB:  100,
		MaxBackups: 7,
		MaxAgeDays: 30,
		Compress:   true,
	},
	Sanitization: SanitizationConfig{
		SensitiveFields: []string{
			"password",
			"token",
			"access_token",
			"refresh_token",
		},
		Mask: "****",
	},
}

func Init(configPath string) error {
	var initErr error
	once.Do(func() {
		var cfg Config
		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				cfg = defaultConfig
			} else {
				initErr = err
				return
			}
		} else {
			if err := json.Unmarshal(data, &cfg); err != nil {
				initErr = err
				return
			}
		}

		encoderConfig := zapcore.EncoderConfig{
			TimeKey:        cfg.EncodingConfig.TimeKey,
			LevelKey:       cfg.EncodingConfig.LevelKey,
			NameKey:        cfg.EncodingConfig.NameKey,
			CallerKey:      cfg.EncodingConfig.CallerKey,
			MessageKey:     cfg.EncodingConfig.MessageKey,
			StacktraceKey:  cfg.EncodingConfig.StacktraceKey,
			LineEnding:     cfg.EncodingConfig.LineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     getZapTimeEncoder(cfg.EncodingConfig.TimeEncoder),
			EncodeDuration: getZapDurationEncoder(cfg.EncodingConfig.DurationEncoder),
			EncodeCaller:   getZapCallerEncoder(cfg.EncodingConfig.CallerEncoder),
		}

		encodeConsole := encoderConfig
		encodeConsole.EncodeLevel = coloredLevelEncoder

		var cores []zapcore.Core
		level := zap.NewAtomicLevelAt(getZapLevel(cfg.Level))

		consoleEncoder := zapcore.NewConsoleEncoder(encodeConsole)
		consoleOutput := zapcore.Lock(os.Stdout)
		consoleCore := zapcore.NewCore(consoleEncoder, consoleOutput, level)
		cores = append(cores, consoleCore)

		for _, path := range cfg.OutputPaths {
			if path != "stdout" && path != "stderr" {
				jsonEncoder := zapcore.NewJSONEncoder(encoderConfig)
				var writer zapcore.WriteSyncer

				if cfg.LogRotation.Enabled {
					lj := ljLogger(path, cfg.LogRotation)
					writer = zapcore.AddSync(lj)
				} else {
					file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
					if err != nil {
						continue
					}
					writer = zapcore.AddSync(file)
				}

				fileCore := zapcore.NewCore(jsonEncoder, writer, level)
				cores = append(cores, fileCore)
			}
		}

		combinedCore := zapcore.NewTee(cores...)

		if len(cfg.Sanitization.SensitiveFields) > 0 {
			combinedCore = NewSanitizerCore(combinedCore,
				cfg.Sanitization.SensitiveFields,
				cfg.Sanitization.Mask)
		}

		// Wrap the combined core with AsyncCore
		asyncCore := NewAsyncCore(combinedCore, 1000, 100, 500*time.Millisecond) // Buffer size of 1000, adjust as needed

		loggerInstance = zap.New(asyncCore,
			zap.AddCaller(),
			zap.AddStacktrace(zap.ErrorLevel),
		)
	})
	return initErr
}

// returns the global *zap.Logger.
// It panics if Init was not called successfully.
func Logger() *zap.Logger {
	if loggerInstance == nil {
		panic("Logger not initialized. Call logger.Init() before using the logger.")
	}
	return loggerInstance
}

// flushes any buffered log entries.
func Sync() error {
	if loggerInstance != nil {
		return loggerInstance.Sync()
	}
	return nil
}

// processes a list of log paths and returns corresponding WriteSyncers.
func createWriteSyncers(paths []string, logRotationEnabled bool, rotationCfg LogRotationConfig, defaultSyncer zapcore.WriteSyncer) []zapcore.WriteSyncer {
	var writeSyncers []zapcore.WriteSyncer
	for _, path := range paths {
		switch path {
		case "stdout":
			// Stdout just writes directly, no rotation
			writeSyncers = append(writeSyncers, zapcore.AddSync(&nopSyncWriter{os.Stdout}))
		case "stderr":
			// Stderr just writes directly, no rotation
			writeSyncers = append(writeSyncers, zapcore.AddSync(&nopSyncWriter{os.Stderr}))
		default:
			if logRotationEnabled {
				lj := ljLogger(path, rotationCfg)
				writeSyncers = append(writeSyncers, zapcore.AddSync(lj))
			} else {
				// If rotation is disabled, just use regular file writing
				writeSyncers = append(writeSyncers, defaultSyncer)
			}
		}
	}
	return writeSyncers
}

// maps string levels to zapcore.Level
func getZapLevel(level string) zapcore.Level {
	switch level {
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

// maps string encoders to zapcore.LevelEncoder
func getZapLevelEncoder(encoder string) zapcore.LevelEncoder {
	switch encoder {
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

// maps string encoders to zapcore.TimeEncoder
func getZapTimeEncoder(encoder string) zapcore.TimeEncoder {
	switch encoder {
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

// maps string encoders to zapcore.DurationEncoder
func getZapDurationEncoder(encoder string) zapcore.DurationEncoder {
	switch encoder {
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

// maps string encoders to zapcore.CallerEncoder
func getZapCallerEncoder(encoder string) zapcore.CallerEncoder {
	switch encoder {
	case "full":
		return zapcore.FullCallerEncoder
	case "short":
		return zapcore.ShortCallerEncoder
	default:
		return zapcore.ShortCallerEncoder
	}
}

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

func ljLogger(path string, l LogRotationConfig) *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   path,
		MaxSize:    l.MaxSizeMB,
		MaxBackups: l.MaxBackups,
		MaxAge:     l.MaxAgeDays,
		Compress:   l.Compress,
	}
}
