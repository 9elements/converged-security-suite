package log

import (
	fianoLog "github.com/linuxboot/fiano/pkg/log"
)

var _ fianoLog.Logger = DummyLogger{}

// DummyLogger is just a placeholder for a logger, which does nothing
type DummyLogger struct{}

func (DummyLogger) Warnf(format string, args ...interface{})  {}
func (DummyLogger) Errorf(format string, args ...interface{}) {}
func (DummyLogger) Fatalf(format string, args ...interface{}) {}
