package logger

// Provides fallback logging settings for any logger not specified in log.config.json.
var DefaultConfig = Config{
	Level:       "info",
	OutputPaths: []string{"stdout"},
	ErrorOutputPaths: []string{
		"stderr",
	},
	Development:  false,
	LogToConsole: false,
	Sampling: Sampling{
		Initial:    100,
		Thereafter: 100,
	},
	Encoding: Encoding{
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
	LogRotation: LogRotation{
		Enabled:    true,
		MaxSizeMB:  100,
		MaxBackups: 7,
		MaxAgeDays: 30,
		Compress:   true,
	},
	Sanitization: Sanitization{
		SensitiveFields: []string{
			"password",
			"token",
			"access_token",
			"refresh_token",
		},
		Mask: "****",
	},
}

func assignDefaultValues(cfg *Config) {
	if cfg.Level == "" {
		cfg.Level = DefaultConfig.Level
	}
	if len(cfg.OutputPaths) == 0 {
		cfg.OutputPaths = DefaultConfig.OutputPaths
	}
	if len(cfg.ErrorOutputPaths) == 0 {
		cfg.ErrorOutputPaths = DefaultConfig.ErrorOutputPaths
	}
	if cfg.Encoding.LevelEncoder == "" {
		cfg.Encoding.LevelEncoder = DefaultConfig.Encoding.LevelEncoder
	}
	if cfg.Encoding.TimeEncoder == "" {
		cfg.Encoding.TimeEncoder = DefaultConfig.Encoding.TimeEncoder
	}
	if cfg.Encoding.DurationEncoder == "" {
		cfg.Encoding.DurationEncoder = DefaultConfig.Encoding.DurationEncoder
	}
	if cfg.Encoding.CallerEncoder == "" {
		cfg.Encoding.CallerEncoder = DefaultConfig.Encoding.CallerEncoder
	}
	if cfg.LogRotation.MaxSizeMB == 0 {
		cfg.LogRotation.MaxSizeMB = DefaultConfig.LogRotation.MaxSizeMB
	}
	if cfg.LogRotation.MaxBackups == 0 {
		cfg.LogRotation.MaxBackups = DefaultConfig.LogRotation.MaxBackups
	}
	if cfg.LogRotation.MaxAgeDays == 0 {
		cfg.LogRotation.MaxAgeDays = DefaultConfig.LogRotation.MaxAgeDays
	}
}
