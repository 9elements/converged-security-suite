package bootpolicy

import (
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/common/pretty"
	"github.com/9elements/converged-security-suite/v2/pkg/provisioning/bootguard/common"
)

// StructInfo is the common header of any element.
type StructInfo = common.StructInfo

// PrettyString: Boot Policy Manifest
type Manifest struct {
	// PrettyString: BPMH: Header
	BPMH `rehashValue:"rehashedBPMH()" json:"bpmHeader"`
	SE   []SE `json:"bpmSE"`
	// PrettyString: PME: Platform Manufacturer
	PME *PM `json:"bpmPME,omitempty"`
	// PrettyString: PMSE: Signature
	PMSE Signature `json:"bpmSignature"`
}

// Print prints the Manifest
func (bpm Manifest) Print() {
	fmt.Printf("%v", bpm.BPMH.PrettyString(1, true))
	for _, item := range bpm.SE {
		fmt.Printf("%v", item.PrettyString(1, true))
	}

	if bpm.PME != nil {
		fmt.Printf("%v\n", bpm.PME.PrettyString(1, true))
	} else {
		fmt.Println("  --PME--\n\tnot set!(optional)")
	}

	if bpm.PMSE.Signature.DataTotalSize() < 1 {
		fmt.Printf("%v\n", bpm.PMSE.PrettyString(1, true, pretty.OptionOmitKeySignature(true)))
		fmt.Printf("  --PMSE--\n\tBoot Policy Manifest not signed!\n\n")
	} else {
		fmt.Printf("%v\n", bpm.PMSE.PrettyString(1, true, pretty.OptionOmitKeySignature(false)))
	}
}
