package cbnt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/tjfoc/gmsm/sm2"

	"github.com/9elements/converged-security-suite/v2/pkg/test"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
)

var (
	fitbpm fit.EntryHeaders
)

var (
	bpmhasfitentry = Test{
		Name:     "BPM Firmware Interface Table has FitEntry",
		function: BPMHasFitEntry,
		Type:     required,
	}
	bpmhstructinfovalid = Test{
		Name:     "BPM BPMH StructInfo",
		function: BPMBPMHStructInfoValid,
		Type:     required,
	}
	bpmbpmhksoffsetvalid = Test{
		Name:     "BPM BPMH Key Signature Offset",
		function: BPMBPMHKeySigOffset,
		Type:     required,
	}
	bpmbpmhrevisionvalid = Test{
		Name:     "BPM BPMH Revision",
		function: BPMBPMHRevisionValid,
		Type:     required,
	}
	bpmbpmhsvnvalid = Test{
		Name:     "BPM BPMH SVN",
		function: BPMBPMHSVNValid,
		Type:     required,
	}
	bpmbpmhacmsvnvalid = Test{
		Name:     "BPM BPMH ACMSVN",
		function: BPMBPMHACMSVNValid,
		Type:     required,
	}
	bpmbpmhreserved0valid = Test{
		Name:     "BPM BPMH Reserved0",
		function: BPMBPMHReserved,
		Type:     required,
	}
	bpmbpmhnemstacksize = Test{
		Name:     "BPM BPMH NemStackSize",
		function: BPMBPMHNemStackSize,
		Type:     required,
	}
	bpmsecount = Test{
		Name:     "BPM SE Count",
		function: BPMSEcount,
		Type:     required,
	}
	bpmseheader = Test{
		Name:     "BPM SE Header",
		function: BPMSEHeaderValid,
		Type:     required,
	}
	bpmseelemsize = Test{
		Name:     "BPM SE Element Size",
		function: BPMSESizeValid,
		Type:     required,
	}
	bpmsereserved = Test{
		Name:     "BPM SE Reserved",
		function: BPMSEReservedValid,
		Type:     required,
	}
	bpmsesetnumber = Test{
		Name:     "BPM SE SetNumber",
		function: BPMSESetNumberValid,
		Type:     required,
	}
	bpmsepbetvalue = Test{
		Name:     "BPM SE BPET Value",
		function: BPMSEBPETValueValid,
		Type:     required,
	}
	bpmseflags = Test{
		Name:     "BPM SE Flags",
		function: BPMSEFalgsValid,
		Type:     required,
	}
	bpmseibbmchbar = Test{
		Name:     "BPM SE IBB_MCHBAR",
		function: BPMSEIBBMCHBARValid,
		Type:     required,
	}
	bpmsevtdbar = Test{
		Name:     "BPM SE VT-d BAR",
		function: BPMSEVTdBARValid,
		Type:     required,
	}
	bpmsedmaprodbase0 = Test{
		Name:     "BPM SE DMAProtBase0",
		function: BPMSEDMAProtBase0Valid,
		Type:     required,
	}
	bpmsedmaprodlimit0 = Test{
		Name:     "BPM SE DMAProtLimit0",
		function: BPMSEDMAProdLimit0Valid,
		Type:     required,
	}
	bpmsedmaprodbase1 = Test{
		Name:     "BPM SE DMAProtBase1",
		function: BPMSEDMAProtBase1Valid,
		Type:     required,
	}
	bpmsedmaprodlimit1 = Test{
		Name:     "BPM SE DMAProtLimit1",
		function: BPMSEDMAProdLimit1Valid,
		Type:     required,
	}
	bpmsepostibbhash = Test{
		Name:     "BPM SE PostIBBHash",
		function: BPMSEPostIBBHashValid,
		Type:     required,
	}
	bpmseibbentrypoint = Test{
		Name:     "BPM SE IBB EntryPoint",
		function: BPMSEIBBEntryPointValid,
		Type:     required,
	}
	bpmsedigestlist = Test{
		Name:     "BPM SE DigestList",
		function: BPMSEDigestListValid,
		Type:     required,
	}
	bpmseobbhash = Test{
		Name:     "BPM SE ObbHash",
		function: BPMSEObbHashValid,
		Type:     required,
	}
	bpmsesegcount = Test{
		Name:     "BPM SE Segment Count",
		function: BPMSESegmentCountValid,
		Type:     required,
	}
	bpmseibbsegments = Test{
		Name:     "BPM SE IBB Segments",
		function: BPMSEIBBSegmentsValid,
		Type:     required,
	}
	bpmtxteheader = Test{
		Name:     "BPM TXTE Header",
		function: BPMTXTEHeaderValid,
		Type:     txte,
	}
	bpmtxtereserved = Test{
		Name:     "BPM TXTE Reserved",
		function: BPMTXTEReservedValid,
		Type:     txte,
	}
	bpmtxtesetnumber = Test{
		Name:     "BPM TXTE SetNumber",
		function: BPMTXTESetNumberValid,
		Type:     txte,
	}
	bpmtxtesinitsvn = Test{
		Name:     "BPM TXTE SInitSVN",
		function: BPMTXTESinitSVMValid,
		Type:     txte,
	}
	bpmtxtecontrolfalgs = Test{
		Name:     "BPM TXTE Control Flags",
		function: BPMTXTEControlFlagsValid,
		Type:     txte,
	}
	bpmtxtepwrdwnival = Test{
		Name:     "BPM TXTE PwrDownInterval",
		function: BPMTXTEPwrDownIntervalValid,
		Type:     txte,
	}
	bpmtxtepttcmosoffset0 = Test{
		Name:     "BPM TXTE PTTCmosOffset0",
		function: BPMTXTEPttCmosOffset0Valid,
		Type:     txte,
	}
	bpmtxtepttcmosoffset1 = Test{
		Name:     "BPM TXTE PTTCmosOffset1",
		function: BPMTXTEPttCmosOffset1Valid,
		Type:     txte,
	}
	bpmtxteacpibaseoffset = Test{
		Name:     "BPM TXTE ACPIBaseOffset",
		function: BPMTXTEACPIBaseOffsetValid,
		Type:     txte,
	}
	bpmtxtepwrmbaseoffset = Test{
		Name:     "BPM TXTE PwrmBaseOffset",
		function: BPMTXTEPwrmBaseOffsetValid,
		Type:     txte,
	}
	bpmtxtedigestlist = Test{
		Name:     "BPM TXTE DigestList",
		function: BPMTXTEDigestListValid,
		Type:     txte,
	}
	bpmtxtesegmentcount = Test{
		Name:     "BPM TXTE Segment Count",
		function: BPMTXTESegmentCount,
		Type:     txte,
	}
	bpmpcdeheader = Test{
		Name:     "BPM PCDE Header",
		function: BPMPCDEHeaderValid,
		Type:     pcde,
	}
	bpmpcdeelementsize = Test{
		Name:     "BPM PCDE Element Size",
		function: BPMPCDEElementSize,
		Type:     pcde,
	}
	bpmpcdesizeofdata = Test{
		Name:     "BPM PCDE SizeOfData",
		function: BPMPCDESizeOfData,
		Type:     pcde,
	}
	bpmpcdedata = Test{
		Name:     "BP PCDE Data",
		function: BPMPCDEData,
		Type:     pcde,
	}
	bpmpmeheader = Test{
		Name:     "BPM PME Header",
		function: BPMPMEHeaderValid,
		Type:     pme,
	}
	bpmpmeelementsize = Test{
		Name:     "BPM PME Element Size",
		function: BPMPMEElementSize,
		Type:     pme,
	}
	bpmpmesizeofdata = Test{
		Name:     "BPM PME Size of Data",
		function: BPMPMESizeOfData,
		Type:     pme,
	}
	bpmpmedata = Test{
		Name:     "BPM PME Data",
		function: BPMPMEData,
		Type:     pme,
	}
	bpmpmseheader = Test{
		Name:     "BPM PMSE Header",
		function: BPMPMSEHeaderValid,
		Type:     required,
	}
	bpmpmsekasverion = Test{
		Name:     "BPM PMSE KeySignature Version",
		function: BPMPMSEKaAVersion,
		Type:     required,
	}
	bpmpmsekaskey = Test{
		Name:     "BPM PMSE Key",
		function: BPMPMSEKaSKey,
		Type:     required,
	}
	bpmpmsekassigscheme = Test{
		Name:     "BPM PMSE Signature Scheme",
		function: BPMPMSEKaSSignatureScheme,
		Type:     required,
	}
	bpmpmsekassigkeysize = Test{
		Name:     "BPM PMSE Signature Key Size",
		function: BPMPMSESigKeySize,
		Type:     required,
	}
	bpmpmsekassighashalg = Test{
		Name:     "BPM PMSE Signature Hash Algorithm",
		function: BPMPMSESigHashAlg,
		Type:     required,
	}
	bpmpmsekassigvalid = Test{
		Name:     "BPM PMSE Signature",
		function: BPMPMSESigData,
		Type:     required,
	}
)

// ImageBPMTests is a slice of all cbnt.Test relating only to BPM
var imageBPMTests = []*Test{
	&bpmhasfitentry,
	&bpmhstructinfovalid,
	&bpmbpmhksoffsetvalid,
	&bpmbpmhrevisionvalid,
	&bpmbpmhsvnvalid,
	&bpmbpmhacmsvnvalid,
	&bpmbpmhreserved0valid,
	&bpmbpmhnemstacksize,
	&bpmsecount,
	&bpmseheader,
	&bpmseelemsize,
	&bpmsereserved,
	&bpmsesetnumber,
	&bpmsepbetvalue,
	&bpmseflags,
	&bpmseibbmchbar,
	&bpmsevtdbar,
	&bpmsedmaprodbase0,
	&bpmsedmaprodlimit0,
	&bpmsedmaprodbase1,
	&bpmsedmaprodlimit1,
	&bpmsepostibbhash,
	&bpmseibbentrypoint,
	&bpmsedigestlist,
	&bpmseobbhash,
	&bpmsesegcount,
	&bpmseibbsegments,
	&bpmtxteheader,
	&bpmtxtereserved,
	&bpmtxtesetnumber,
	&bpmtxtesinitsvn,
	&bpmtxtecontrolfalgs,
	&bpmtxtepttcmosoffset0,
	&bpmtxtepttcmosoffset1,
	&bpmtxteacpibaseoffset,
	&bpmtxtepwrmbaseoffset,
	&bpmtxtedigestlist,
	&bpmtxtesegmentcount,
	&bpmpcdeheader,
	&bpmpcdeelementsize,
	&bpmpcdesizeofdata,
	&bpmpcdedata,
	&bpmpmeheader,
	&bpmpmeelementsize,
	&bpmpmesizeofdata,
	&bpmpmedata,
	&bpmpmseheader,
	&bpmpmsekasverion,
	&bpmpmsekaskey,
	&bpmpmsekassigscheme,
	&bpmpmsekassigkeysize,
	&bpmpmsekassighashalg,
	&bpmpmsekassigvalid,
}

// BPMHasFitEntry defines the behavior for the Test "BPM HasFitEntry"
func BPMHasFitEntry() (bool, error) {
	var found bool
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, item := range fitentries {
		if item.Type() == fit.EntryTypeBootPolicyManifest {
			found = true
		}
	}
	if !found {
		return false, fmt.Errorf("No BPM Entry in FIT found")
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
	if objUnderTest.bpm.BPMH.ID.String() != structID {
		s.WriteString("BPM Header ID invalid. Have: " + objUnderTest.bpm.BPMH.ID.String() + " Want: " + structID)
	}
	if objUnderTest.bpm.BPMH.Version != structVersion {
		s.WriteString("BPM Header Version invalid. Have: " + fmt.Sprintf("0x%x", objUnderTest.bpm.BPMH.Version) + " Want: " + fmt.Sprintf("0x%x", structVersion))
	}
	if objUnderTest.bpm.BPMH.Variable0 != hdrstructVrsion {
		s.WriteString("BPM Header HdrStructVersion invalid. Have: " + fmt.Sprintf("%d", objUnderTest.bpm.BPMH.Variable0) + " Want: " + fmt.Sprintf("%d", hdrstructVrsion))
	}
	if uint16(binary.Size(objUnderTest.bpm.BPMH)) != hdrSize {
		s.WriteString("BPM Header HdrSize invalid. Have: " + fmt.Sprintf("%d", uint16(binary.Size(objUnderTest.bpm.BPMH))) + " Want: " + fmt.Sprintf("%d", hdrSize))
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
	if (uint64(objUnderTest.bpm.KeySignatureOffset) - objUnderTest.bpm.PMSEOffset()) != 12 {
		s.WriteString("BPM KeySignatureOffset invalid. Must be 12 Bytes ahead of PMSEOffset. KeySignatureOffset: " +
			fmt.Sprintf("%d", objUnderTest.bpm.KeySignatureOffset) + " PMSEOffset: " + fmt.Sprintf("%d", objUnderTest.bpm.PMSEOffset()))
	}
	// If the distance of KeySignatureOffset and PMSEOffset is correct. We need to back that up.
	// Get bpm address from FIT, add KeySignatureOffset, minus 12 Bytes and we should arrive at PMSE ID
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, entry := range fitentries {
		if entry.Type() == fit.EntryTypeBootPolicyManifest {
			fitbpm = entry
		}
	}
	// Get the BPM Offset from FIT
	bpmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitbpm.Address.Pointer())
	if err != nil {
		return false, err
	}
	// BPM offset + bpm.KeySignatureOffset - 12 Bytes = bpm.PMSE.ID
	bpmPMSEoffset := bpmoffset + uint64(objUnderTest.bpm.KeySignatureOffset) - uint64(12)
	// PMSE.ID is 8 Byte in size
	tmpSigHdrB := make([]byte, 8)
	// Copy BPM.PMSE.ID (8 Bytes) from the image
	copy(tmpSigHdrB[:], objUnderTest.image[bpmPMSEoffset:bpmPMSEoffset+8])
	if string(tmpSigHdrB) != "__PMSG__" {
		s.WriteString("BPM KeySignatureOffset invalid. Can't find BPM.PMSE.ID at offset: " + fmt.Sprintf("%d", bpmPMSEoffset) + ". KeySignature should be at: " + fmt.Sprintf("%d", bpmPMSEoffset+12))
	}
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMBPMHRevisionValid defines the behavior for the Test "BPM BPMH Revision"
func BPMBPMHRevisionValid() (bool, error) {
	if objUnderTest.bpm.BPMH.BPMRevision < 1 {
		return false, fmt.Errorf("BPM BPMH Revision is zero. Must be greater than 0. This indicates a development Revision")
	}
	return true, nil
}

// BPMBPMHSVNValid defines the behavior for the Test "BPM BPMH SVN"
func BPMBPMHSVNValid() (bool, error) {
	if objUnderTest.bpm.BPMH.BPMSVN.SVN() < 1 && objUnderTest.bpm.BPMH.BPMSVN.SVN() > 15 {
		return false, fmt.Errorf("BPM BPMH SVN invalid. Must be between 1 and 15, but SVN is: %d", objUnderTest.bpm.BPMH.BPMSVN.SVN())
	}
	return true, nil
}

// BPMBPMHACMSVNValid defines the behavior for the Test "BPM BPMH ACMSVN"
func BPMBPMHACMSVNValid() (bool, error) {
	if objUnderTest.bpm.BPMH.ACMSVNAuth.SVN() < 2 {
		return false, fmt.Errorf("BPM BPMH SVN is smaller than 2. This indicates a non production ACM")
	}
	if objUnderTest.bpm.BPMH.ACMSVNAuth.SVN() > 15 {
		return false, fmt.Errorf("BPM BPMH SVN is invalid. Must be smaller than 15. ACMSVN is: %d", objUnderTest.bpm.BPMH.ACMSVNAuth.SVN())
	}
	return true, nil
}

// BPMBPMHReserved defines the behavior for the Test "BPM BPMH Reserved0"
func BPMBPMHReserved() (bool, error) {
	if objUnderTest.bpm.BPMH.Reserved0 != [1]byte{0} {
		return false, fmt.Errorf("BPM BPMH Reserved0 must be zero. Have: %d", objUnderTest.bpm.BPMH.Reserved0)
	}
	return true, nil
}

// BPMBPMHNemStackSize defines the behavior for the Test "BPM BPMH NemStackSize"
func BPMBPMHNemStackSize() (bool, error) {
	return true, fmt.Errorf("Needs to be implemented yet")
}

// BPMSEcount defines the behavior for the Test "BPM SE Count"
func BPMSEcount() (bool, error) {
	if len(objUnderTest.bpm.SE) != 1 {
		return false, fmt.Errorf("BPM SE count invalid. One instance supported, but have: %d", len(objUnderTest.bpm.SE))
	}
	return true, nil
}

// BPMSEHeaderValid defines the behavior for the Test "BPM SE Header"
func BPMSEHeaderValid() (bool, error) {
	var s strings.Builder
	// Only one element is allowed anyway, so we just check the first element.
	se := objUnderTest.bpm.SE[0]
	headerID := "__IBBS__"
	headerVersion := uint8(0x20)
	if se.StructInfo.ID.String() != headerID {
		s.WriteString("BPMSE Header ID incorrect. Have: " + se.StructInfo.ID.String() + " - Want: " + string(headerID))
	}
	if se.StructInfo.Version != headerVersion {
		s.WriteString("BPMSE Header Version incorrect. Have: " + string(se.StructInfo.Version) + " - Want: " + string(headerVersion))
	}
	if se.StructInfo.Variable0 != 0 {
		s.WriteString("BPMSE Header Variable0 incorrect. Have: " + string(se.StructInfo.Variable0) + " - Want: 0")
	}
	if s.Len() != 0 {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMSESizeValid defines the behavior for the Test "BPM SE Size"
func BPMSESizeValid() (bool, error) {
	// Fixed sizes of structure
	fSize := uint16(80)
	// Variable sizes of HashBuffer PostIBBHash HashBuffer, ObbHashHashBuffer, DigestList.List, IBB_Segments
	se := objUnderTest.bpm.SE[0]
	// PostIBBHash digest fiel (HashBuffer, variable size)
	fSize += uint16(len(se.PostIBBHash.HashBuffer))
	// DigestList List (variable size)
	for _, item := range se.DigestList.List {
		// DigestList - list entry - algo (2 bytes, fixed size)
		fSize += 2
		// DigestList Count (2 Bytes, fixed)
		fSize += 2
		// HashBuffer size (variable)
		fSize += uint16(len(item.HashBuffer))
	}
	// ObbHash like PostIBBHash
	fSize += uint16(len(se.OBBHash.HashBuffer))
	// IBB_Segments are fixed size (12 Bytes) but in a slice
	for range se.IBBSegments {
		fSize += 12
	}
	if fSize != se.ElementSize {
		return false, fmt.Errorf("BPM SE Element Size invalid. Have %d - Want: %d", se.ElementSize, fSize)
	}
	return true, nil
}

// BPMSEReservedValid defines the behavior for the Test "BPM SE Reserved"
func BPMSEReservedValid() (bool, error) {
	if objUnderTest.bpm.SE[0].Reserved0 != [1]byte{0} {
		return false, fmt.Errorf("BPM SE Reserved0 must be zero. Have: %d", objUnderTest.bpm.SE[0].Reserved0)
	}
	if objUnderTest.bpm.SE[0].Reserved1 != [1]byte{0} {
		return false, fmt.Errorf("BPM SE Reserved1 must be zero. Have: %d", objUnderTest.bpm.SE[0].Reserved1)
	}
	if objUnderTest.bpm.SE[0].Reserved2 != [3]byte{0, 0, 0} {
		return false, fmt.Errorf("BPM SE Reserved2 must be zero. Have: %d", objUnderTest.bpm.SE[0].Reserved2)
	}
	return true, nil
}

// BPMSESetNumberValid defines the behavior for the Test "BPM SE SetNumber"
func BPMSESetNumberValid() (bool, error) {
	if objUnderTest.bpm.SE[0].SetNumber != 0 {
		return false, fmt.Errorf("BPM SE SetNumber must be zero. Have: %d", objUnderTest.bpm.SE[0].SetNumber)
	}
	return true, nil
}

// BPMSEBPETValueValid defines the behavior for the Test "BPM SE BPETValue"
func BPMSEBPETValueValid() (bool, error) {
	if objUnderTest.bpm.SE[0].PBETValue.PBETValue() < 1 && objUnderTest.bpm.SE[0].PBETValue.PBETValue() > 15 {
		return false, fmt.Errorf("BPM SE PBET Value invalid. Have: %d - Want: Value between 1 and 15", objUnderTest.bpm.SE[0].PBETValue.PBETValue())
	}
	return true, nil
}

// BPMSEFalgsValid defines the behavior for the Test "BPM SE Flags"
func BPMSEFalgsValid() (bool, error) {
	var s strings.Builder
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, entry := range fitentries {
		if entry.Type() == fit.EntryTypeBootPolicyManifest {
			fitbpm = entry
		}
	}
	// Get the BPM Offset from FIT
	bpmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitbpm.Address.Pointer())
	if err != nil {
		return false, err
	}
	// Calc the SE Flags Offset
	seFlagsOffset := bpmoffset + objUnderTest.bpm.SEOffset() + objUnderTest.bpm.SE[0].FlagsOffset()
	flagsByte := make([]byte, 4)
	// Copy the four flags bytes from the image
	copy(flagsByte, objUnderTest.image[seFlagsOffset:seFlagsOffset+4])
	flagsUint, _ := binary.Uvarint(flagsByte)
	// The upper 3 Bytes are not used, so just for padding?
	if (1 >> (flagsUint & 0x1)) != 0 {
		s.WriteString("BPM SE Flags invalid. LSB must be 1")
	}
	if (1 >> (flagsUint & 0x2)) != 0 {
		s.WriteString("BPM SE Flags invalid. LSB+1 must be 1")
	}
	if (1 >> (flagsUint & 0xFFFFFFF0)) != 0 {
		s.WriteString("BPM SE Flags invalid. MSB to MSB - 3 Bytes must be zero")
	}
	return true, nil
}

// BPMSEIBBMCHBARValid defines the behavior for the Test "BPM SE IBB_MCHBAR"
func BPMSEIBBMCHBARValid() (bool, error) {
	if objUnderTest.bpm.SE[0].IBBMCHBAR != 0 {
		return false, fmt.Errorf("BPM SE IBB MCHBAR invalid. Must be zero")
	}
	return true, nil
}

// BPMSEVTdBARValid defines the behavior for the Test "BPM SE VT-d BAR"
func BPMSEVTdBARValid() (bool, error) {
	if objUnderTest.bpm.SE[0].VTdBAR != 0 {
		return false, fmt.Errorf("BPM SE VT-d BAR invalid. Must be zero")
	}
	return true, nil
}

// BPMSEDMAProtBase0Valid defines the behavior for the Test "BPM SE DMAProtBase0"
func BPMSEDMAProtBase0Valid() (bool, error) {
	if uint64(objUnderTest.bpm.SE[0].DMAProtBase0) > test.FourGiB {
		return false, fmt.Errorf("BPM SE DMA ProtBase0 invalid. Must be below 4 GiB")
	}
	return true, nil
}

// BPMSEDMAProdLimit0Valid defines the behavior for the Test "BPM SE DMAProtLimit0""
func BPMSEDMAProdLimit0Valid() (bool, error) {
	if uint64(objUnderTest.bpm.SE[0].DMAProtLimit0) > test.FourGiB {
		return false, fmt.Errorf("BPM SE DMA ProtLimit0 invalid. Must be below 4 GiB")
	}
	return true, nil
}

// BPMSEDMAProtBase1Valid defines the behavior for the Test "BPM SE DMAProtBase0"
func BPMSEDMAProtBase1Valid() (bool, error) {
	if uint64(objUnderTest.bpm.SE[0].DMAProtBase1) > test.FourGiB {
		return false, fmt.Errorf("BPM SE DMA ProtBase1 invalid. Must be below 4 GiB")
	}
	return true, nil
}

// BPMSEDMAProdLimit1Valid defines the behavior for the Test "BPM SE DMAProtLimit0""
func BPMSEDMAProdLimit1Valid() (bool, error) {
	if uint64(objUnderTest.bpm.SE[0].DMAProtLimit1) > test.FourGiB {
		return false, fmt.Errorf("BPM SE DMA ProtLimit1 invalid. Must be below 4 GiB")
	}
	return true, nil
}

// BPMSEPostIBBHashValid defines the behavior for the Test "BPM SE PostIBBHash"
func BPMSEPostIBBHashValid() (bool, error) {
	// PostIBBHash is legacy and moved to PCDE structure
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, entry := range fitentries {
		if entry.Type() == fit.EntryTypeBootPolicyManifest {
			fitbpm = entry
		}
	}
	// Get the BPM Offset from FIT
	bpmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitbpm.Address.Pointer())
	if err != nil {
		return false, err
	}
	// Calc the SE PostIbbHash Offset
	sePostIbbHashOffset := bpmoffset + objUnderTest.bpm.SEOffset() + objUnderTest.bpm.SE[0].PostIBBHashOffset()
	postibbhashBytes := make([]byte, 4)
	copy(postibbhashBytes, objUnderTest.image[sePostIbbHashOffset:sePostIbbHashOffset+4])

	if bytes.Equal(postibbhashBytes, []byte{0}) {
		return false, fmt.Errorf("BPM SE PostIBBHash invalid. Must be 4 Bytes of zero")
	}
	return true, nil
}

// BPMSEIBBEntryPointValid defines the behavior for the Test "BPM SE IBB EntryPoint"
func BPMSEIBBEntryPointValid() (bool, error) {
	if int(objUnderTest.bpm.SE[0].IBBEntryPoint) > test.FourGiB {
		return false, fmt.Errorf("BPM SE IBB EntryPoint invalid. Have: %d - Want: smaler than %d", objUnderTest.bpm.SE[0].IBBEntryPoint, test.FourGiB)
	}
	return true, nil
}

// BPMSEDigestListValid defines the behavior for the Test "BPM SE DigestList"
func BPMSEDigestListValid() (bool, error) {
	// We need to extract the IBBs, hash them and compare the hash to the values set in this structure.
	for count, ibb := range objUnderTest.bpm.SE[0].IBBSegments {
		// Get offset of ibb
		ibboffset, err := tools.CalcImageOffset(objUnderTest.image, uint64(ibb.Base))
		if err != nil {
			return false, err
		}
		// Extract ibb with address
		ibbbyte := make([]byte, ibb.Size)
		copy(ibbbyte, objUnderTest.image[ibboffset:ibboffset+uint64(ibb.Size)])
		// The first IBB Segment maps to the first three entries of DigestList
		list := objUnderTest.bpm.SE[0].DigestList.List
		for i := 0; i < count+3; i++ {
			h, err := list[i].HashAlg.Hash()
			if err != nil {
				return false, err
			}
			h.Reset()
			h.Write(ibbbyte)
			hs := h.Sum(nil)
			if !bytes.Equal(list[i].HashBuffer, hs) {
				return false, fmt.Errorf("Hash %s does not match the hash of the IBB Segment on adress: %d", list[i].HashAlg.String(), ibb.Base)
			}
		}
	}
	return true, nil
}

// BPMSEObbHashValid defines the behavior for the Test "BPM SE ObbHash"
func BPMSEObbHashValid() (bool, error) {
	// ObbHash is legacy and moved to PCDE structure
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, entry := range fitentries {
		if entry.Type() == fit.EntryTypeBootPolicyManifest {
			fitbpm = entry
		}
	}
	// Get the BPM Offset from FIT
	bpmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitbpm.Address.Pointer())
	if err != nil {
		return false, err
	}
	// Calc the SE ObbHash Offset
	seOBBHashOffset := bpmoffset + objUnderTest.bpm.SEOffset() + objUnderTest.bpm.SE[0].OBBHashOffset()
	obbhashBytes := make([]byte, 4)
	copy(obbhashBytes, objUnderTest.image[seOBBHashOffset:seOBBHashOffset+4])

	if bytes.Equal(obbhashBytes, []byte{0}) {
		return false, fmt.Errorf("BPM SE PostIBBHash invalid. Must be 4 Bytes of zero")
	}
	return true, nil
}

// BPMSESegmentCountValid defines the behavior for the Test "BPM SE Segment Count"
func BPMSESegmentCountValid() (bool, error) {
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, entry := range fitentries {
		if entry.Type() == fit.EntryTypeBootPolicyManifest {
			fitbpm = entry
		}
	}
	// Get the BPM Offset from FIT
	bpmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitbpm.Address.Pointer())
	if err != nil {
		return false, err
	}
	// SegmentCount is three Bytes after the SE[0].Reserved2 field
	segCountOffset := bpmoffset + objUnderTest.bpm.SEOffset() + objUnderTest.bpm.SE[0].Reserved2Offset() + 3
	segCountByte := make([]byte, 1)
	copy(segCountByte, objUnderTest.image[segCountOffset:segCountOffset+1])
	r := bytes.NewReader(segCountByte)
	var sCount uint8
	if err := binary.Read(r, binary.BigEndian, &sCount); err != nil {
		return false, err
	}
	if int(sCount) != len(objUnderTest.bpm.SE[0].IBBSegments) {
		return false, fmt.Errorf("BPM SE Segment Count invalid. Have: %d - Want: %d", int(sCount), len(objUnderTest.bpm.SE[0].IBBSegments))
	}
	return true, nil
}

// BPMSEIBBSegmentsValid defines the behavior for the Test "BPM SE IBB Segments"
func BPMSEIBBSegmentsValid() (bool, error) {
	var s strings.Builder
	for _, ibb := range objUnderTest.bpm.SE[0].IBBSegments {
		if ibb.Reserved != [2]byte{0, 0} {
			s.WriteString("BPM SE IBB Segement Reserved invalid. Must be 2 Bytes of zero")
		}
		if int(ibb.Base) > test.FourGiB {
			s.WriteString("BPM SE IBB Segement Base invalid. Have: " + fmt.Sprintf("%d", ibb.Base) + " - Want: below 4 GiB")
		}
		if int(ibb.Base+ibb.Size) > test.FourGiB {
			s.WriteString("BPM SE IBB Segment Size invalid. IBB Base + IBB Size must be below 4 GiB")
		}
	}
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMTXTEHeaderValid defines the behavior for the Test "BPM TXTE Header"
func BPMTXTEHeaderValid() (bool, error) {
	var s strings.Builder
	txte := objUnderTest.bpm.TXTE
	txteHeaderID := "__TXTS__"

	if txte.StructInfo.ID.String() != txteHeaderID {
		s.WriteString("BPM TXTE Header Structure ID invalid. Have: " + txte.StructInfo.ID.String() + " Want: " + txteHeaderID)
	}
	if txte.StructInfo.Version != 0x21 {
		s.WriteString("BPM TXTE Header Structure Version invalid. Have: " + fmt.Sprintf("0x%x", txte.StructInfo.Version) + " Want: 0x21")
	}
	if txte.StructInfo.Variable0 != 0 {
		s.WriteString("BPM TXTE Header Structure Reserved invalid. Have: " + fmt.Sprintf("%d", txte.StructInfo.Variable0) + " Want: 0")
	}
	eSize := uint16(40)
	for _, elem := range txte.DigestList.List {
		// 2 Bytes for Algo
		eSize += 2
		// 2 Bytes for Size
		eSize += 2
		eSize += uint16(len(elem.HashBuffer))
	}
	if txte.StructInfo.ElementSize != eSize {
		s.WriteString("BPM TXTE Header ElemenSize invalid. Have " + fmt.Sprintf("%d", txte.StructInfo.ElementSize) + " Want: " + fmt.Sprintf("%d", eSize))
	}
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMTXTEReservedValid defines the behavior for the Test "BPM TXTE Reserved"
func BPMTXTEReservedValid() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	var s strings.Builder
	if txte.Reserved0 != [1]byte{0} {
		s.WriteString("BPM TXTE Reserved0 invalid. Must be zero")
	}
	if txte.Reserved1 != [1]byte{0} {
		s.WriteString("BPM TXTE Reserved1 invalid. Must be zero")
	}
	if txte.Reserved2 != [2]byte{0, 0} {
		s.WriteString("BPM TXTE Reserved2 invalid. Must be zero")
	}
	if txte.Reserved3 != [3]byte{0, 0, 0} {
		s.WriteString("BPM TXTE Reserved3 invalid. Must be zero")
	}
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMTXTESetNumberValid defines the behavior for the Test "BPM TXTE SetNumber"
func BPMTXTESetNumberValid() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	if txte.SetNumber != [1]byte{0} {
		return false, fmt.Errorf("BPM TXTE SetNumber invalid. Must be zero")
	}
	return true, nil
}

// BPMTXTESinitSVMValid defines the behavior for the Test "BPM TXTE SInitSVN"
func BPMTXTESinitSVMValid() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	if txte.SInitMinSVNAuth == 0 {
		return true, fmt.Errorf("BPM TXTE SInitMinSVN not set")
	}
	return true, nil
}

// BPMTXTEControlFlagsValid defines the behavior for the Test "BPM TXTE Control Flags"
func BPMTXTEControlFlagsValid() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	if txte.ControlFlags == 0 {
		return true, fmt.Errorf("BPM TXTE Control Falgs not set")
	}
	return true, nil
}

// BPMTXTEPwrDownIntervalValid defines the behavior for the Test "BPM TXTE PwrDownInterval"
func BPMTXTEPwrDownIntervalValid() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	if txte.PwrDownInterval.String() == "0" {
		return true, fmt.Errorf("BPM TXTE PwrDownInterval not set")
	}
	return true, nil
}

// BPMTXTEPttCmosOffset0Valid defines the behavior for the Test "BPM TXTE PTTCmosOffset0"
func BPMTXTEPttCmosOffset0Valid() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	if txte.PTTCMOSOffset0 == 0 {
		return false, fmt.Errorf("BPM TXTE PttCmosOffset0 invalid. Must not be zero")
	}
	return true, nil
}

// BPMTXTEPttCmosOffset1Valid defines the behavior for the Test "BPM TXTE PTTCmosOffset1"
func BPMTXTEPttCmosOffset1Valid() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	if txte.PTTCMOSOffset1 == 0 {
		return false, fmt.Errorf("BPM TXTE PttCmosOffset1 invalid. Must not be zero")
	}
	return true, nil
}

// BPMTXTEACPIBaseOffsetValid defines the behavior for the Test "BPM TXTE ACPIBaseOffset"
func BPMTXTEACPIBaseOffsetValid() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	if txte.ACPIBaseOffset == 0 {
		return false, fmt.Errorf("BPM TXTE ACPIBaseOffset invalid. Must not be zero")
	}
	return true, nil
}

// BPMTXTEPwrmBaseOffsetValid defines the behavior for the Test "BPM TXTE PwrmBaseOffset"
func BPMTXTEPwrmBaseOffsetValid() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	if txte.PwrMBaseOffset == 0 {
		return false, fmt.Errorf("BPM TXTE PwrmBaseOffset invalid. Must not be zero")
	}
	return true, nil
}

// BPMTXTEDigestListValid defines the behavior for the Test "BPM TXTE DigestList"
func BPMTXTEDigestListValid() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	var s strings.Builder
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, entry := range fitentries {
		if entry.Type() == fit.EntryTypeBootPolicyManifest {
			fitbpm = entry
		}
	}
	// Get the BPM Offset from FIT
	bpmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitbpm.Address.Pointer())
	if err != nil {
		return false, err
	}
	txteDLoffset := bpmoffset + objUnderTest.bpm.TXTEOffset() + txte.DigestListOffset()
	// DigestList Size = 4, Count = 0, Digest = empty => 4 Byte
	txteDLBytes := make([]byte, 4)
	copy(txteDLBytes, objUnderTest.image[txteDLoffset:txteDLoffset+4])
	var dlSize, dlCount uint16
	r := bytes.NewReader(txteDLBytes)
	if err := binary.Read(r, binary.LittleEndian, &dlSize); err != nil {
		return false, err
	}
	if err := binary.Read(r, binary.LittleEndian, &dlCount); err != nil {
		return false, err
	}
	if dlSize != 4 {
		s.WriteString("BPM TXTE DigestList Size invalid. Must be 0x04")
	}
	if dlCount != 0 {
		s.WriteString(" BPM TXTE DigestList Count invalid. Must be 0x00")
	}
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMTXTESegmentCount defines the behavior for the Test "BPM TXTE Segment Count"
func BPMTXTESegmentCount() (bool, error) {
	txte := objUnderTest.bpm.TXTE
	if txte.SegmentCount != 0 {
		return false, fmt.Errorf("BPM TXTE Segment Count invalid. Must be zero")
	}
	return true, nil
}

// BPMPCDEHeaderValid defines the behavior for the Test "BPM PCDE Header"
func BPMPCDEHeaderValid() (bool, error) {
	pcde := objUnderTest.bpm.PCDE
	pcdeID := "__PCDS__"
	var s strings.Builder
	if pcde.StructInfo.ID.String() != pcdeID {
		s.WriteString("BPM PCDS Header ID invalid. Have: " + fmt.Sprintf("%s", pcde.StructInfo.ID.String()) + " Want: " + fmt.Sprintf("%s", pcdeID))
	}
	if pcde.StructInfo.Version != 0x20 {
		s.WriteString("BPM PCDS Header Version invalid. Have: " + fmt.Sprintf("0x%x", pcde.StructInfo.Version) + " Want: 0x20")
	}
	if pcde.StructInfo.Variable0 != 0x00 {
		s.WriteString("BPM PCDS Header Reserved invalid. Have: " + fmt.Sprintf("0x%x", pcde.StructInfo.Variable0) + " Want: 0x00")
	}
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMPCDEElementSize defines the behavior for the Test "BPM PCDE ElementSize"
func BPMPCDEElementSize() (bool, error) {
	pcde := objUnderTest.bpm.PCDE
	fSize := uint16(16)
	fSize += uint16(len(pcde.Data))
	if pcde.ElementSize != fSize {
		return false, fmt.Errorf("BPM PCDE Element Size invalid. Have: 0x%x - Want: 0x%x", pcde.ElementSize, fSize)
	}
	return true, nil
}

// BPMPCDESizeOfData defines the behavior for the Test "BPM PCDE SizeOfData"
func BPMPCDESizeOfData() (bool, error) {
	pcde := objUnderTest.bpm.PCDE
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, entry := range fitentries {
		if entry.Type() == fit.EntryTypeBootPolicyManifest {
			fitbpm = entry
		}
	}
	// Get the BPM Offset from FIT
	bpmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitbpm.Address.Pointer())
	if err != nil {
		return false, err
	}
	// SizeOfData element 2 Byts after Reserved0
	pcdeSizeOffset := bpmoffset + objUnderTest.bpm.PCDEOffset() + pcde.Reserved0Offset() + 2
	sByte := make([]byte, 2)
	var size uint16
	copy(sByte, objUnderTest.image[pcdeSizeOffset:pcdeSizeOffset+2])
	r := bytes.NewReader(sByte)
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return false, err
	}
	if uint16(len(pcde.Data)) != size {
		return false, fmt.Errorf("BPM PCDE SizeOfData invalid. Have: %d - Want: %d", uint16(len(pcde.Data)), size)
	}
	return true, nil
}

// BPMPCDEData defines the behavior for the Test "BPM PCDE Data"
func BPMPCDEData() (bool, error) {
	return true, fmt.Errorf("BPM PCDE Data: Cant validate PCDE Data (yet)")
}

// BPMPMEHeaderValid defines the behavior for the Test "BPM PME Header"
func BPMPMEHeaderValid() (bool, error) {
	pme := objUnderTest.bpm.PME
	pmeID := "__PMDA__"
	var s strings.Builder
	if pme.StructInfo.ID.String() != pmeID {
		s.WriteString("BPM PME Header ID invalid. Have: " + fmt.Sprintf("%s", pme.StructInfo.ID.String()) + " Want: " + fmt.Sprintf("%s", pmeID))
	}
	if pme.StructInfo.Version != 0x20 {
		s.WriteString("BPM PME Header Version invalid. Have: " + fmt.Sprintf("0x%x", pme.StructInfo.Version) + " Want: 0x20")
	}
	if pme.StructInfo.Variable0 != 0x00 {
		s.WriteString("BPM PME Header Reserved invalid. Have: " + fmt.Sprintf("0x%x", pme.StructInfo.Variable0) + " Want: 0x00")
	}
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMPMEElementSize defines the behavior for the Test "BPM PME Element Size"
func BPMPMEElementSize() (bool, error) {
	pme := objUnderTest.bpm.PME
	fSize := uint16(16)
	fSize += uint16(len(pme.Data))
	if pme.ElementSize != fSize {
		return false, fmt.Errorf("BPM PME Element Size invalid. Have: 0x%x - Want: 0x%x", pme.ElementSize, fSize)
	}
	return true, nil
}

// BPMPMESizeOfData defines the behavior for the Test "BPM PME SizeOfData"
func BPMPMESizeOfData() (bool, error) {
	pme := objUnderTest.bpm.PME
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, entry := range fitentries {
		if entry.Type() == fit.EntryTypeBootPolicyManifest {
			fitbpm = entry
		}
	}
	// Get the BPM Offset from FIT
	bpmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitbpm.Address.Pointer())
	if err != nil {
		return false, err
	}
	// SizeOfData element 2 Byts after Reserved0
	pcdeSizeOffset := bpmoffset + objUnderTest.bpm.PMEOffset() + pme.Reserved0Offset() + 2
	sByte := make([]byte, 2)
	var size uint16
	copy(sByte, objUnderTest.image[pcdeSizeOffset:pcdeSizeOffset+2])
	r := bytes.NewReader(sByte)
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return false, err
	}
	if uint16(len(pme.Data)) != size {
		return false, fmt.Errorf("BPM PCDE SizeOfData invalid. Have: %d - Want: %d", uint16(len(pme.Data)), size)
	}
	return true, nil
}

// BPMPMEData defines the behavior for the Test "BPM PME Data"
func BPMPMEData() (bool, error) {
	return true, fmt.Errorf("BPM PME Data: Cant validate PME Data (yet)")
}

// BPMPMSEHeaderValid defines the behavior for the Test "BPM PMSE Header"
func BPMPMSEHeaderValid() (bool, error) {
	pmse := objUnderTest.bpm.PMSE
	pmseID := "__PMSG__"
	var s strings.Builder
	if pmse.StructInfo.ID.String() != pmseID {
		s.WriteString("BPM PMSE Header ID invalid. Have: " + fmt.Sprintf("%s", pmse.StructInfo.ID.String()) + " Want: " + fmt.Sprintf("%s", pmseID))
	}
	if pmse.StructInfo.Version != 0x20 {
		s.WriteString("BPM PMSE Header Version invalid. Have: " + fmt.Sprintf("0x%x", pmse.StructInfo.Version) + " Want: 0x20")
	}
	if pmse.StructInfo.Variable0 != 0x00 {
		s.WriteString("BPM PMSE Header Reserved invalid. Have: " + fmt.Sprintf("0x%x", pmse.StructInfo.Variable0) + " Want: 0x00")
	}
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMPMSEKaAVersion defines the behavior for the Test "BPM PMSE KeySignature Version"
func BPMPMSEKaAVersion() (bool, error) {
	kAs := objUnderTest.bpm.PMSE.KeySignature
	if kAs.Version != 0x10 {
		return false, fmt.Errorf("BPM PMSE KeySignature Verion invalid. Have: 0x%x - Want: 0x10", kAs.Version)
	}
	return true, nil
}

// BPMPMSEKaSKey defines the behavior for the Test "BPM PMSE Key"
func BPMPMSEKaSKey() (bool, error) {
	var s strings.Builder
	kAsKey := objUnderTest.bpm.PMSE.KeySignature.Key
	bpmpubkey, err := objUnderTest.bpmpubkey.PubKey()
	if err != nil {
		return false, err
	}

	if kAsKey.Version != 0x10 {
		s.WriteString("BPM PMSE Key Version invalid. Have: " + fmt.Sprintf("0x%x", kAsKey.Version) + " Want: 0x10")
	}
	switch key := bpmpubkey.(type) {
	case *rsa.PublicKey:
		if kAsKey.KeyAlg != manifest.AlgRSA {
			s.WriteString("BPM PMSE KeySignature Key Algorithm invalid. Given key is of type RSA. Set key is " + fmt.Sprintf("%v", key))
		}
		if uint16(key.Size()) != kAsKey.KeySize.InBytes() {
			s.WriteString("BPM PMSE KeySignature Key Size invalid. Have: " + fmt.Sprintf("%d", kAsKey.KeySize) + " Want: " + fmt.Sprintf("%d", key.Size()))
		}
	case *ecdsa.PublicKey:
		if kAsKey.KeyAlg != manifest.AlgECDSA {
			return false, fmt.Errorf("BPM PMSE KeySignature Key Algorithm invalid. Given key is of type ECDSA. Set key is " + fmt.Sprintf("%v", key))
		}
		if kAsKey.KeySize.InBits() != 256 {
			s.WriteString("BPM PMSE KeySignature Key Size invalid. Have: " + fmt.Sprintf("%d", kAsKey.KeySize) + " Want: 256")
		}
	case *sm2.PublicKey:
		if kAsKey.KeyAlg != manifest.AlgSM2 {
			return false, fmt.Errorf("BPM PMSE KeySignature Key Algorithm invalid. Given key is of type SM2. Set key is " + fmt.Sprintf("%v", key))
		}
		if kAsKey.KeySize.InBits() != 256 {
			s.WriteString("BPM PMSE KeySignature Key Size invalid. Have: " + fmt.Sprintf("%d", kAsKey.KeySize) + " Want: 256")
		}
	default:
		return false, fmt.Errorf("BPM PMSE KeySignature Key Algorithm invalid. Algorithm unknown")
	}

	if !bytes.Equal(objUnderTest.bpmpubkey.Data, kAsKey.Data) {
		s.WriteString("BPM PMSE KeySignature Key invalid. Given key and set key are not equal.")
	}
	if s.String() != "" {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// BPMPMSEKaSSignatureScheme defines the behavior for the Test "BPM PMSE Signature Scheme"
func BPMPMSEKaSSignatureScheme() (bool, error) {
	var e strings.Builder
	var err error
	if objUnderTest.bpm.PMSE.Key.KeyAlg == manifest.AlgRSA && objUnderTest.bpm.PMSE.Signature.SigScheme != manifest.AlgRSASSA {
		_, err = e.WriteString("SigScheme invalid for key set. Key is of type RSA but SigScheme is not RSASSA")
	}

	if objUnderTest.bpm.PMSE.Signature.SigScheme == manifest.AlgRSASSA && objUnderTest.bpm.PMSE.Key.KeyAlg != manifest.AlgRSA {
		_, err = e.WriteString("Set Key is invalid for SigScheme set. SigScheme is RSASSA but key is not of type RSA")
	}

	if objUnderTest.bpmpubkey.KeyAlg == manifest.AlgRSA && objUnderTest.bpm.PMSE.Signature.SigScheme != manifest.AlgRSASSA {
		_, err = e.WriteString("SigScheme invalid for key given. Key is of type RSA but SigScheme is not RSASSA")
	}

	if objUnderTest.bpm.PMSE.Signature.SigScheme == manifest.AlgRSASSA && objUnderTest.bpmpubkey.KeyAlg != manifest.AlgRSA {
		_, err = e.WriteString("Given Key is invalid for SigScheme set. SigScheme is RSASSA but key is not of type RSA")
	}

	if objUnderTest.bpm.PMSE.Key.KeyAlg == manifest.AlgECDSA && objUnderTest.bpm.PMSE.Signature.SigScheme != manifest.AlgECDSA {
		_, err = e.WriteString("SigScheme invalid for key set. Key is of type ECDSA but SigScheme is not ECDSA")
	}

	if objUnderTest.bpm.PMSE.Signature.SigScheme == manifest.AlgECDSA && objUnderTest.bpm.PMSE.Key.KeyAlg != manifest.AlgECDSA {
		_, err = e.WriteString("Set Key is invalid for SigScheme set. SigScheme is ECDSA but key is not of type ECDSA")
	}

	if objUnderTest.bpmpubkey.KeyAlg == manifest.AlgECDSA && objUnderTest.bpm.PMSE.Signature.SigScheme != manifest.AlgECDSA {
		_, err = e.WriteString("SigScheme invalid for key given. Key is of type ECDSA but SigScheme is not ECDSA")
	}

	if objUnderTest.bpm.PMSE.Signature.SigScheme == manifest.AlgECDSA && objUnderTest.bpmpubkey.KeyAlg != manifest.AlgECDSA {
		_, err = e.WriteString("Given Key is invalid for SigScheme set. SigScheme is ECDSA but key is not of type ECDSA")
	}

	if objUnderTest.bpm.PMSE.Key.KeyAlg == manifest.AlgSM2 && objUnderTest.bpm.PMSE.Signature.SigScheme != manifest.AlgSM2 {
		_, err = e.WriteString("SigScheme invalid for key set. Key is of type SM2 but SigScheme is not SM2")
	}

	if objUnderTest.bpm.PMSE.Signature.SigScheme == manifest.AlgECDSA && objUnderTest.bpm.PMSE.Key.KeyAlg != manifest.AlgECDSA {
		_, err = e.WriteString("Set Key is invalid for SigScheme set. SigScheme is SM2 but key is not of type SM2")
	}

	if objUnderTest.bpmpubkey.KeyAlg == manifest.AlgECDSA && objUnderTest.bpm.PMSE.Signature.SigScheme != manifest.AlgECDSA {
		_, err = e.WriteString("SigScheme invalid for key given. Key is of type SM2 but SigScheme is not SM2")
	}

	if objUnderTest.bpm.PMSE.Signature.SigScheme == manifest.AlgECDSA && objUnderTest.bpmpubkey.KeyAlg != manifest.AlgECDSA {
		_, err = e.WriteString("Given Key is invalid for SigScheme set. SigScheme is SM2 but key is not of type SM2")
	}
	if err != nil {
		return false, err
	}
	if e.String() != "" {
		return false, fmt.Errorf("%s", e.String())
	}
	return true, nil
}

// BPMPMSESigKeySize defines the behavior for the Test "BPM PMSE Signature Keysize"
func BPMPMSESigKeySize() (bool, error) {
	if objUnderTest.bpm.PMSE.Signature.KeySize.InBits() != objUnderTest.bpm.PMSE.Key.KeySize.InBits() {
		return false, fmt.Errorf("BPM Signature Key size invalid compared to the set key. Have: %d Byte - Want: %d Byte", objUnderTest.bpm.PMSE.Signature.KeySize.InBits(), objUnderTest.km.KeyAndSignature.Key.KeySize.InBits())
	}
	return true, nil
}

// BPMPMSESigHashAlg defines the behavior for the Test "BPM PMSE Signature Hash Alg"
func BPMPMSESigHashAlg() (bool, error) {
	k, err := objUnderTest.bpm.PMSE.Key.PubKey()
	if err != nil {
		return false, err
	}
	switch k.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		if objUnderTest.bpm.PMSE.Signature.HashAlg != manifest.AlgSHA256 && objUnderTest.bpm.PMSE.Signature.HashAlg != manifest.AlgSHA384 {
			return false, fmt.Errorf("KM Signature Key is RSA or ECDSA. Hash algorithm invalid. Must be SHA256 or SHA384. Have: %v", objUnderTest.bpm.PMSE.Signature.HashAlg.String())
		}
	case *sm2.PublicKey:
		if objUnderTest.bpm.PMSE.Signature.HashAlg != manifest.AlgSM3 {
			return false, fmt.Errorf("KM Signature Key is SM2. Hash algorithm invalid. Must be SM3_256. Have: %v", objUnderTest.bpm.PMSE.Signature.HashAlg.String())
		}
	default:
		return false, fmt.Errorf("Unknown Signature Key set")
	}
	return true, nil
}

// BPMPMSESigData defines the behavior for the Test "BPM PMSE Signature Data"
func BPMPMSESigData() (bool, error) {
	ft, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, item := range ft {
		if item.Type() == fit.EntryTypeBootPolicyManifest {
			fitbpm = item
		}
	}
	bpmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitbpm.Address.Pointer())
	if err != nil {
		return false, err
	}
	bpmdata := make([]byte, objUnderTest.bpm.BPMH.KeySignatureOffset)
	copy(bpmdata, objUnderTest.image[bpmoffset:bpmoffset+uint64(objUnderTest.bpm.BPMH.KeySignatureOffset)])
	pkey, err := objUnderTest.bpmpubkey.PubKey()
	if err != nil {
		return false, err
	}
	if err := validateSignature(&objUnderTest.bpm.PMSE.Signature, bpmdata, pkey); err != nil {
		return false, err
	}
	return true, nil
}
