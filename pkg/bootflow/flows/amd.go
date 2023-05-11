package flows

import (
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actors/amdactors"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/commonconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/conditions/tpmconds"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/amdsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/commonsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/steps/tpmsteps"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
)

// this flows were reconstructed by looking into TPM EventLog, so they might be wrong.

var AMD = NewFlow("AMD", types.Steps{
	commonsteps.SetFlow(AMDGenoa),
})

var AMDGenoa = NewFlow("AMDGenoa", types.Steps{
	commonsteps.SetFlow(AMDGenoaLocality3),
	commonsteps.Panic("this case is not implemented, yet"),
})

var AMDGenoaLocality3V2 = NewFlow("AMDGenoaLocality3V2", types.Steps{
	commonsteps.SetActor(amdactors.PSP{}),
	amdsteps.VerifyPSPDirectory(AMDGenoaVerificationFailureV2),
	tpmsteps.InitTPM(3, true),
	amdsteps.MeasurePSPVersion{},
	amdsteps.MeasureBIOSRTMVolume{},
	commonsteps.SetFlow(AMDGenoaLocality0V2),
})

var AMDGenoaVerificationFailureV2 = NewFlow("AMDGenoaVerificationFailureV2", types.Steps{
	commonsteps.SetFlow(AMDGenoaLocality0V2),
})

var AMDGenoaLocality0V2 = NewFlow("AMDGenoaLocality0V2", types.Steps{
	commonsteps.If(commonconds.Not(tpmconds.TPMIsInited{}), tpmsteps.InitTPM(0, false), nil),
	tpmsteps.Measure(0, tpmeventlog.EV_NO_ACTION, (*datasources.StaticData)(types.NewForcedData([]byte{0x8d, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x50}))),
	amdsteps.MeasureEmbeddedFirmwareStructure{},
	amdsteps.MeasureBIOSDirectory{},
	amdsteps.MeasureBIOSStaticEntries{},
	amdsteps.MeasurePMUFirmware{},
	amdsteps.MeasureMicrocodePatch{},
	amdsteps.MeasureVideoImageInterpreter{},
	commonsteps.SetFlow(PEI),
})

var AMDGenoaLocality3 = NewFlow("AMDGenoaLocality3", types.Steps{
	commonsteps.SetActor(amdactors.PSP{}),
	amdsteps.VerifyPSPDirectory(AMDGenoaVerificationFailure),
	tpmsteps.InitTPM(3, true),
	amdsteps.MeasurePSPVersion{},
	amdsteps.MeasureBIOSRTMVolume{},
	commonsteps.SetFlow(AMDGenoaLocality0),
})

var AMDGenoaVerificationFailure = NewFlow("AMDGenoaVerificationFailure", types.Steps{
	commonsteps.SetFlow(AMDGenoaLocality0),
})

var AMDGenoaLocality0 = NewFlow("AMDGenoaLocality0", types.Steps{
	commonsteps.If(commonconds.Not(tpmconds.TPMIsInited{}), tpmsteps.InitTPM(0, false), nil),
	amdsteps.MeasureMP0C2PMsgRegisters{},
	amdsteps.MeasureEmbeddedFirmwareStructure{},
	amdsteps.MeasureBIOSDirectory{},
	amdsteps.MeasureBIOSStaticEntries{},
	amdsteps.MeasurePMUFirmware{},
	amdsteps.MeasureMicrocodePatch{},
	amdsteps.MeasureVideoImageInterpreter{},
	commonsteps.SetFlow(PEI),
})
