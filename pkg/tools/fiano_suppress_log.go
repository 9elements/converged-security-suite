package tools

import (
	"io"
	"log"
	"runtime"
	"strings"
)

type noFianoWriter struct {
	Backend io.Writer
}

func (w noFianoWriter) Write(b []byte) (int, error) {
	_, file, _, _ := runtime.Caller(4)
	if strings.Contains(file, "github.com/linuxboot/fiano") {
		return len(b), nil
	}

	return w.Backend.Write(b)
}

// See: https://github.com/linuxboot/fiano/issues/330
func suppressFianoLog() func() {
	origWriter := log.Writer()
	log.SetOutput(noFianoWriter{Backend: origWriter})
	return func() {
		log.SetOutput(origWriter)
	}
}
