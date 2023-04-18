package pcrbruteforcer

import (
	"context"
	"reflect"
	"testing"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/bootengine"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/diff"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/facebookincubator/go-belt/tool/logger"
	"github.com/facebookincubator/go-belt/tool/logger/implementation/logrus"
)

func Test_logEntryExplanation_guessMeasurementFromEventRanges(t *testing.T) {
	ctx := logger.CtxWithLogger(context.Background(), logrus.Default().WithLevel(logger.LevelTrace))

	type fields struct {
		Measurement     *types.MeasuredData
		RelatedNodes    []diff.NodeInfo
		EventDataParsed *tpmeventlog.EventDataParsed
		DigestGuesses   [][]byte
	}
	type args struct {
		expectedMeasurement *types.MeasuredData
		ev                  *tpmeventlog.Event
		image               *biosimage.BIOSImage
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *types.MeasuredData
		want1  []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := types.NewState()
			s.IncludeSubSystem(tpm.NewTPM())
			process := bootengine.NewBootProcess(s)
			process.Finish(ctx)
			e := logEntryExplanation{
				Measurement:     tt.fields.Measurement,
				RelatedNodes:    tt.fields.RelatedNodes,
				EventDataParsed: tt.fields.EventDataParsed,
				DigestGuesses:   tt.fields.DigestGuesses,
			}
			got, got1 := e.guessMeasurementFromEventRanges(ctx, s, tt.args.expectedMeasurement, tt.args.ev, tt.args.image)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("logEntryExplanation.guessMeasurementFromEventRanges() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("logEntryExplanation.guessMeasurementFromEventRanges() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
