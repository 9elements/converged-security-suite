package cbnt

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/tools"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
)

var (
	fitbpm fit.EntryHeaders
)

var (
	bpmhasfitentry = Test{
		Name:     "BPM Firmware Interface Table has FitEntry",
		function: BPMHasFitEntry,
	}
	bpmhstructinfovalid = Test{
		Name:     "BPM BPMH StructInfo",
		function: BPMBPMHStructInfoValid,
	}
	bpmbpmhksoffset = Test{
		Name:     "BPM BPMH Key Signature Offset",
		function: BPMBPMHKeySigOffset,
	}
)

// ImageBPMTests is a slice of all cbnt.Test relating only to BPM
var ImageBPMTests = []*Test{
	&bpmhasfitentry,
	&bpmhstructinfovalid,
	&bpmbpmhksoffset,
}

// BPMHasFitEntry defines the behavior for the Test "BPM HasFitEntry"
func BPMHasFitEntry() (bool, error) {
	var found bool
	fitentries, err := fit.GetTable(image)
	if err != nil {
		return false, err
	}
	for _, item := range fitentries {
		if item.Type() == fit.EntryTypeBootPolicyManifest {
			found = true
		}
	}
	if !found {
		return false, fmt.Errorf("No KM Entry in FIT found")
	}
	return true, nil
}

// BPMBPMHStructInfoValid defines the behavior for the Test "BPM BPMH StructInfo Valid"
func BPMBPMHStructInfoValid() (bool, error) {
	var s strings.Builder
	// BPMStructureID is a fixed value which represents the string "__ACBP__"
	structID := "__ACBP__"
	// BPMStructureVersion is a fixed value of 0x23
	structVersion := uint8(0x23)
	// hdrStructVersion is fixed value of 0x20
	hdrstructVrsion := uint8(0x20)
	// BPMH is a fixed size structure of 20 Bytes
	hdrSize := uint16(20)
	if bpm.BPMH.ID.String() != structID {
		s.WriteString("BPM Header ID invalid. Have: " + bpm.BPMH.ID.String() + " Want: " + structID)
	}
	if bpm.BPMH.Version != structVersion {
		s.WriteString("BPM Header Version invalid. Have: " + fmt.Sprintf("%d", bpm.BPMH.Version) + " Want: " + fmt.Sprintf("%d", structVersion))
	}
	if bpm.BPMH.Variable0 != hdrstructVrsion {
		s.WriteString("BPM Header HdrStructVersion invalid. Have: " + fmt.Sprintf("%d", bpm.BPMH.Variable0) + " Want: " + fmt.Sprintf("%d", hdrstructVrsion))
	}
	if uint16(binary.Size(bpm.BPMH)) != hdrSize {
		s.WriteString("BPM Header HdrSize invalid. Have: " + fmt.Sprintf("%d", uint16(binary.Size(bpm.BPMH))) + " Want: " + fmt.Sprintf("%d", hdrSize))
	}
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMBPMHKeySigOffset defines the behavior for the Test "BPM BPMH Key Signature Offset"
func BPMBPMHKeySigOffset() (bool, error) {
	// Calculating the offset by summing up the size of the substructures is just inefficient.
	// Instead I take the given Offset, add it to the BPM offset from the FitTable and read the
	// first 8 Bytes. The first 8 Byte should contain the string "__PMSG__" if so => offset is correct.
	var s strings.Builder
	// Check if KeySignatureOffset is exactly 12 Bytes ahead of PMSEOffset
	if (uint64(bpm.KeySignatureOffset) - bpm.PMSEOffset()) != 12 {
		s.WriteString("BPM KeySignatureOffset invalid. Must be 12 Bytes ahead of PMSEOffset. KeySignatureOffset: " +
			fmt.Sprintf("%d", bpm.KeySignatureOffset) + " PMSEOffset: " + fmt.Sprintf("%d", bpm.PMSEOffset()))
	}
	// If the distance of KeySignatureOffset and PMSEOffset is correct. We need to back that up.
	// Get bpm address from FIT, add KeySignatureOffset, minus 12 Bytes and we should arrive at PMSE ID
	fitentries, err := fit.GetTable(image)
	if err != nil {
		return false, err
	}
	for _, entry := range fitentries {
		if entry.Type() == fit.EntryTypeBootPolicyManifest {
			fitbpm = entry
		}
	}
	// Get the BPM Offset from FIT
	bpmoffset, err := tools.CalcImageOffset(image, fitbpm.Address.Pointer())
	if err != nil {
		return false, err
	}
	// BPM offset + bpm.KeySignatureOffset - 12 Bytes = bpm.PMSE.ID
	bpmPMSEoffset := bpmoffset + uint64(bpm.KeySignatureOffset) - uint64(12)
	// PMSE.ID is 8 Byte in size
	tmpSigHdrB := make([]byte, 8)
	// Copy BPM.PMSE.ID (8 Bytes) from the image
	copy(tmpSigHdrB[:], image[bpmPMSEoffset:bpmPMSEoffset+8])
	if string(tmpSigHdrB) != "__PMSG__" {
		s.WriteString("BPM KeySignatureOffset invalid. Can't find BPM.PMSE.ID at offset: " + fmt.Sprintf("%d", bpmPMSEoffset))
	}
	// ToDo: Still need to calculate or count offset manually for verification.....
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}

	return true, nil
}
