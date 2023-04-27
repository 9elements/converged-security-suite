package pcrbruteforcer

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

type IssueUnexpectedLogEntry struct {
	Index             int
	Event             *tpmeventlog.Event
	LogEntryExplainer *logEntryExplainer
}

func (e IssueUnexpectedLogEntry) Error() string {
	return fmt.Sprintf(
		"unexpected entry in EventLog of type %s and digest %X on evIdx==%d; log entry analysis: %s",
		e.Event.Type, e.Event.Digest.Digest, e.Index, e.LogEntryExplainer,
	)
}

type IssueLoggedDigestDoesNotMatch struct {
	Index             int
	Measurement       *types.MeasuredData
	CalculatedDigest  types.ConvertedBytes
	Event             *tpmeventlog.Event
	LogEntryExplainer *logEntryExplainer
}

func (e IssueLoggedDigestDoesNotMatch) Error() string {
	return fmt.Sprintf(
		"measurement '%s' does not match the digest reported in EventLog: calculated:%s != given:0x%X; log entry analysis: %s",
		e.Measurement, e.CalculatedDigest, e.Event.Digest.Digest, e.LogEntryExplainer,
	)
}
