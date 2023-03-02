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
)

var AMD = types.Flow{
	commonsteps.SetFlow(AMDGenoa),
}

var AMDGenoa = types.Flow{
	commonsteps.SetFlow(AMDGenoaLocality3V2),
	commonsteps.SetFlow(AMDGenoaLocality3),
	commonsteps.Panic("this case is not implemented, yet"),
}

var AMDGenoaLocality3V2 = types.Flow{
	commonsteps.SetActor(amdactors.PSP{}),
	amdsteps.VerifyPSPDirectory(AMDGenoaVerificationFailureV2),
	tpmsteps.InitTPM(3),
	amdsteps.MeasurePSPVersion{},
	amdsteps.MeasureBIOSRTMVolume{},
	commonsteps.SetFlow(AMDGenoaLocality0V2),
}

var AMDGenoaVerificationFailureV2 = types.Flow{
	commonsteps.SetFlow(AMDGenoaLocality0V2),
}

var AMDGenoaLocality0V2 = types.Flow{
	commonsteps.If(commonconds.Not(tpmconds.TPMIsInited{}), tpmsteps.InitTPM(0)),
	tpmsteps.Measure(0, &datasources.StaticData{ForceBytes: []byte{0x8d, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x50}}),
	amdsteps.MeasureEmbeddedFirmwareStructure{},
	amdsteps.MeasureBIOSDirectory{},
	amdsteps.MeasureBIOSStaticEntries{},
	amdsteps.MeasurePMUFirmware{},
	amdsteps.MeasureMicrocodePatch{},
	amdsteps.MeasureVideoImageInterpreter{},
	commonsteps.SetFlow(PEI),
}

var AMDGenoaLocality3 = types.Flow{
	commonsteps.SetActor(amdactors.PSP{}),
	amdsteps.VerifyPSPDirectory(AMDGenoaVerificationFailure),
	tpmsteps.InitTPM(3),
	amdsteps.MeasurePSPVersion{},
	amdsteps.MeasureBIOSRTMVolume{},
	commonsteps.SetFlow(AMDGenoaLocality0),
}

var AMDGenoaVerificationFailure = types.Flow{
	commonsteps.SetFlow(AMDGenoaLocality0),
}

var AMDGenoaLocality0 = types.Flow{
	commonsteps.If(commonconds.Not(tpmconds.TPMIsInited{}), tpmsteps.InitTPM(0)),
	amdsteps.MeasureMP0C2PMsgRegisters{},
	amdsteps.MeasureEmbeddedFirmwareStructure{},
	amdsteps.MeasureBIOSDirectory{},
	amdsteps.MeasureBIOSStaticEntries{},
	amdsteps.MeasurePMUFirmware{},
	amdsteps.MeasureMicrocodePatch{},
	amdsteps.MeasureVideoImageInterpreter{},
	commonsteps.SetFlow(PEI),
}
