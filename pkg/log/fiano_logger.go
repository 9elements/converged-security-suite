package log

import (
	"github.com/facebookincubator/go-belt/tool/logger"
	fianoLog "github.com/linuxboot/fiano/pkg/log"
)

var _ fianoLog.Logger = FianoLogger{}

// FianoLogger is an implementation of a fiano/pkg/log.Logger based
// on go-belt's Logger. Fiano is pretty noisy on low-important problems,
// so we enforce another logging level.
type FianoLogger struct {
	Backend    logger.Logger
	LogAsLevel logger.Level
}

// NewFianoLogger returns a new instance of FianoLogger.
//
// Argument "log" is the actual logger used to log, and all non-fatal the logs
// are logged with the specified logging level "logAsLevel".
func NewFianoLogger(log logger.Logger, logAsLevel logger.Level) *FianoLogger {
	return &FianoLogger{
		Backend:    log,
		LogAsLevel: logAsLevel,
	}
}

func (l FianoLogger) Warnf(format string, args ...interface{}) {
	if l.Backend == nil {
		return
	}
	l.Backend.Logf(l.LogAsLevel, "[warn] "+format, args...)
}
func (l FianoLogger) Errorf(format string, args ...interface{}) {
	if l.Backend == nil {
		return
	}
	l.Backend.Logf(l.LogAsLevel, "[error] "+format, args...)
}
func (l FianoLogger) Fatalf(format string, args ...interface{}) {
	if l.Backend == nil {
		logger.Default().Fatalf(format, args...)
		return
	}
	l.Backend.Fatalf(format, args...)
}
