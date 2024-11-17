package logger

// Provides fallback logging settings for any logger not specified in log.config.json.
var DefaultConfig = Config{
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
	if cfg.EncodingConfig.LevelEncoder == "" {
		cfg.EncodingConfig.LevelEncoder = DefaultConfig.EncodingConfig.LevelEncoder
	}
	if cfg.EncodingConfig.TimeEncoder == "" {
		cfg.EncodingConfig.TimeEncoder = DefaultConfig.EncodingConfig.TimeEncoder
	}
	if cfg.EncodingConfig.DurationEncoder == "" {
		cfg.EncodingConfig.DurationEncoder = DefaultConfig.EncodingConfig.DurationEncoder
	}
	if cfg.EncodingConfig.CallerEncoder == "" {
		cfg.EncodingConfig.CallerEncoder = DefaultConfig.EncodingConfig.CallerEncoder
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
