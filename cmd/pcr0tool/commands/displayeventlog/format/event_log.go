package format

import (
	"fmt"
	"strings"

	"github.com/davecgh/go-spew/spew"

	"github.com/9elements/converged-security-suite/v2/pkg/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// PCRIndexPtr is just a replacement for ugly &[]pcr.ID{in}[0]
func PCRIndexPtr(in pcr.ID) *pcr.ID {
	return &in
}

// HashAlgoPtr is just a replacement for ugly &[]tpmeventlog.TPMAlgorithm{in}[0]
func HashAlgoPtr(in tpmeventlog.TPMAlgorithm) *tpmeventlog.TPMAlgorithm {
	return &in
}

// EventLog returns a string with a formatted TPM EventLog.
func EventLog(
	eventLog *tpmeventlog.TPMEventLog,
	filterPCRIndex *pcr.ID,
	filterHashAlgo *tpmeventlog.TPMAlgorithm,
	prefix string,
	isMultiline bool,
) string {
	var result strings.Builder

	if !isMultiline {
		result.WriteString(fmt.Sprintf("%s  #\tidx\t      type\thash\tdigest\tdata\n", prefix))
	}
	for idx, ev := range eventLog.Events {
		if filterPCRIndex != nil && *filterPCRIndex != ev.PCRIndex {
			continue
		}

		var hash tpmeventlog.TPMAlgorithm
		var digest []byte
		if ev.Digest != nil {
			hash = ev.Digest.HashAlgo
			digest = ev.Digest.Digest
		}
		if filterHashAlgo != nil && (ev.Digest == nil || hash != *filterHashAlgo) {
			continue
		}

		if isMultiline {
			writeField := func(fieldName, valueFormat string, value interface{}) {
				result.WriteString(fmt.Sprintf("%s%-20s: "+valueFormat+"\n", prefix, fieldName, value))
			}
			writeField("#", "%d", idx)
			writeField("PCR index", "%d", ev.PCRIndex)
			writeField("Event Type", "%d", ev.Type)
			writeField("Hash Algorithm", "%d", hash)
			writeField("Digest", "%X", digest)
			dataDump := (&spew.ConfigState{Indent: prefix + "    > "}).Sdump(ev.Data)
			writeField("Data", "%s", dataDump)
		} else {
			result.WriteString(fmt.Sprintf("%s%3d\t%2d\t%10d\t%3d\t%X\t%X\n", prefix, idx, ev.PCRIndex, ev.Type, hash, digest, ev.Data))
		}
	}

	return result.String()
}
