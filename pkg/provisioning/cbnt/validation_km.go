package cbnt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/fit"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest"
	"github.com/9elements/converged-security-suite/v2/pkg/intel/metadata/manifest/key"
	"github.com/9elements/converged-security-suite/v2/pkg/tools"
	"github.com/tjfoc/gmsm/sm2"
)

// Declaration of KM Tests
var (
	kmhasFitEntry = Test{
		Name:     "KM HasFitEntry",
		function: KMHasValidFitEntry,
		Type:     required,
	}
	kmValidHeader = Test{
		Name:     "KM Header",
		function: KMStructureValidHeader,
		Type:     required,
	}
	kmValidKMSigOffset = Test{
		Name:     "KM Signature Offset",
		function: KMStructureValidKMSOffset,
		Type:     required,
	}
	kmValidReserverd2 = Test{
		Name:     "KM Reserved2",
		function: KMStructureValidReserved2,
		Type:     required,
	}
	kmrevisionvalid = Test{
		Name:     "KM Revision",
		function: KMStructureValidRevision,
		Type:     required,
	}
	kmsvnvalid = Test{
		Name:     "KM SVN",
		function: KMStructureValidSVN,
		Type:     required,
	}
	kmidvalid = Test{
		Name:     "KM ID",
		function: KMStructureValidID,
		Type:     required,
	}
	kmpubkeyhash = Test{
		Name:     "KM Pub Key Hash Alg",
		function: KMStructureValidKMPubHashAlg,
		Type:     required,
	}
	kmkeyhashcount = Test{
		Name:     "KM Key Hash Count",
		function: KMStructureValidKeyHashCount,
		Type:     required,
	}
	kmbpmkeyhash = Test{
		Name:     "KM BPM Pub Key Hash",
		function: KMStructureValidHashBPM,
		Type:     required,
	}
	kmsigversion = Test{
		Name:     "KM Signature Version",
		function: KMStructureValidSignatureVersion,
		Type:     required,
	}
	kmsigkey = Test{
		Name:     "KM Signature Key",
		function: KMStructureValidSignatureKey,
		Type:     required,
	}
	kmsigscheme = Test{
		Name:     "KM Signature Scheme",
		function: KMStructureValidSignatureSigSchemeCheck,
		Type:     required,
	}
	kmsigkeysize = Test{
		Name:     "KM Signature Key Size",
		function: KMStructureValidSigKeySize,
		Type:     required,
	}
	kmsighashalg = Test{
		Name:     "KM Signature Hash Alg",
		function: KMStructureValidSigHashAlg,
		Type:     required,
	}
	kmsigdata = Test{
		Name:     "KM Signature Data",
		function: KMStructureValidSigData,
		Type:     required,
	}
)

var imageKMTests = []*Test{
	&kmhasFitEntry,
	&kmValidHeader,
	&kmValidKMSigOffset,
	&kmValidReserverd2,
	&kmrevisionvalid,
	&kmsvnvalid,
	&kmidvalid,
	&kmpubkeyhash,
	&kmkeyhashcount,
	&kmbpmkeyhash,
	&kmsigversion,
	&kmsigkey,
	&kmsigscheme,
	&kmsigkeysize,
	&kmsighashalg,
	&kmsigdata,
}

// KMHasValidFitEntry defines the behavior for the Test "KM HasFitEntry"
func KMHasValidFitEntry() (bool, error) {
	var found uint8
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, item := range fitentries {
		if item.Type() == fit.EntryTypeKeyManifestRecord {
			found++
		}
	}
	if found < 1 {
		return false, fmt.Errorf("No KM Entry in FIT found")
	}
	return true, nil
}

// KMStructureValidHeader defines the behavior for the Test "KM Header"
func KMStructureValidHeader() (bool, error) {
	var s strings.Builder
	km := objUnderTest.km
	headerID := "__KEYM__"
	headerVersion := uint8(0x21)
	if km.StructInfo.ID.String() != headerID {
		s.WriteString("KM Header ID incorrect. Have: " + km.StructInfo.ID.String() + " - Want: " + string(headerID))
	}
	if km.StructInfo.Version != headerVersion {
		s.WriteString("KM Header Version incorrect. Have: " + string(km.StructInfo.Version) + " - Want: " + string(headerVersion))
	}
	if km.StructInfo.Variable0 != 0 {
		s.WriteString("KM Header Variable0 incorrect. Have: " + string(km.StructInfo.Variable0) + " - Want: 0")
	}
	if s.Len() != 0 {
		return false, fmt.Errorf("%s", s.String())
	}
	return true, nil
}

// KMStructureValidKMSOffset defines the behavior for the Test "KM Signature Offset"
func KMStructureValidKMSOffset() (bool, error) {
	var KMSigOffset uint16
	//Count the bytes to Key Manifest Signature - Everything is static with the exception KeyHash and Key Manifest Signature
	KMSigOffset = 24
	// Count KMHashes
	for _, hash := range objUnderTest.km.Hash {
		// Usage field 8 bytes static
		KMSigOffset += 8
		// Algorithm field 2 bytes static
		KMSigOffset += 2
		// Size field 2 bytes static
		KMSigOffset += 2
		// Actual length of hash
		KMSigOffset += uint16(len(hash.Digest.HashBuffer))
	}
	if objUnderTest.km.KeyManifestSignatureOffset != KMSigOffset {
		return false, fmt.Errorf("Key Signature Offset incorrect. Have: %d - Want: %d", objUnderTest.km.KeyManifestSignatureOffset, KMSigOffset)
	}
	return true, nil
}

// KMStructureValidReserved2 defines the behavior for the Test "KM Reserved2"
func KMStructureValidReserved2() (bool, error) {
	if objUnderTest.km.Reserved2 != [3]byte{0} {
		return false, fmt.Errorf("KM Reserved2 field invalid. Have: %d - Want: %d", objUnderTest.km.Reserved2, 0)
	}
	return true, nil
}

// KMStructureValidRevision defines the behavior for the Test "KM Revision"
func KMStructureValidRevision() (bool, error) {
	if objUnderTest.km.Revision == 0 {
		return true, fmt.Errorf("KM Revision is zero. This indicates a development Revision")
	}
	return true, nil
}

// KMStructureValidSVN defines the behavior for the Test "KM SVN"
func KMStructureValidSVN() (bool, error) {
	if objUnderTest.km.KMSVN == 0 {
		return true, fmt.Errorf("KM SVN is zero. This indicates a development Security Version Number")
	}
	return true, nil
}

// KMStructureValidID defines the behavior for the Test "KM ID"
func KMStructureValidID() (bool, error) {
	if objUnderTest.km.KMID < 1 || objUnderTest.km.KMID > 15 {
		return false, fmt.Errorf("KM KMID invalid. Have: %v - Want: 0 <= KMID <= 15", objUnderTest.km.KMID)
	}
	return true, nil
}

// KMStructureValidKMPubHashAlg defines the behavior for the Test "KM Pub Key Hash Alg"
func KMStructureValidKMPubHashAlg() (bool, error) {
	if objUnderTest.km.PubKeyHashAlg != manifest.AlgSHA256 && objUnderTest.km.PubKeyHashAlg != manifest.AlgSHA384 && objUnderTest.km.PubKeyHashAlg != manifest.AlgSM3 {
		return false, fmt.Errorf("KM Pub Key Hash Algorithm must be SHA256, SHA384 or SM3")
	}
	return true, nil
}

// KMStructureValidKeyHashCount defines the behavior for the Test "KM KeyHash Count"
func KMStructureValidKeyHashCount() (bool, error) {
	// This is a tricky one. The Count field is written to the image, but implied in the km.Hash field.
	var count uint16
	var fitkm fit.EntryHeaders
	fitentries, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	for _, item := range fitentries {
		if item.Type() == fit.EntryTypeKeyManifestRecord {
			fitkm = item
		}
	}
	countoffset := uint64(22)
	kmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitkm.Address.Pointer())
	if err != nil {
		return false, err
	}
	r := bytes.NewReader(objUnderTest.image[kmoffset+countoffset:])
	err = binary.Read(r, binary.LittleEndian, &count)
	if err != nil {
		return false, err
	}
	if int(count) != len(objUnderTest.km.Hash) {
		return false, fmt.Errorf("KeyHashCount field not equal to amount of KeyHashes")
	}
	return true, nil
}

// KMStructureValidHashBPM defines the behavior for the Test "KM BPM Pub Key Hash"
func KMStructureValidHashBPM() (bool, error) {
	var givenhash, sethash []byte
	givenbpmhash, err := GetBPMPubHash(bpmpubkeypath, objUnderTest.km.PubKeyHashAlg)
	if err != nil {
		return false, err
	}
	for _, hash := range givenbpmhash {
		if hash.Usage.IsSet(key.UsageBPMSigningPKD) {
			if hash.Digest.HashAlg == objUnderTest.km.PubKeyHashAlg {
				givenhash = hash.Digest.HashBuffer
			}

		}
	}
	for _, hash := range objUnderTest.km.Hash {
		if hash.Usage.IsSet(key.UsageBPMSigningPKD) {
			if hash.Digest.HashAlg == objUnderTest.km.PubKeyHashAlg {
				sethash = hash.Digest.HashBuffer
			}
		}
	}
	if !bytes.Equal(givenhash, sethash) {
		return false, fmt.Errorf("BPM Pub key hash in image is invalid to given key")
	}
	return true, nil
}

// KMStructureValidSignatureVersion defines the behavior for the Test "KM Signature Version"
func KMStructureValidSignatureVersion() (bool, error) {
	if objUnderTest.km.KeyAndSignature.Version != 0x10 {
		return false, fmt.Errorf("KM Signature Version field invalid. Have: %v - Want: %v", objUnderTest.km.KeyAndSignature.Version, 0x10)
	}
	return true, nil
}

// KMStructureValidSignatureKey defines the behavior for the Test "KM Signature Key"
func KMStructureValidSignatureKey() (bool, error) {
	var err error
	var e strings.Builder

	if objUnderTest.km.KeyAndSignature.Key.KeyAlg != objUnderTest.kmpubkey.KeyAlg {
		_, err = e.WriteString("Given Key algorithm doesn't match set Key algorithm")
	}
	if objUnderTest.km.KeyAndSignature.Key.Version != objUnderTest.kmpubkey.Version {
		_, err = e.WriteString("Signature.Key.Version invalid. Have: " + fmt.Sprintf("%v", objUnderTest.km.KeyAndSignature.Key.Version) + "Want: 0x10")
	}

	if objUnderTest.km.KeyAndSignature.Key.KeySize.InBits() != objUnderTest.kmpubkey.KeySize.InBits() {
		_, err = e.WriteString("Keysize invalid. Want: " + fmt.Sprintf("%d", objUnderTest.kmpubkey.KeySize.InBits()) + " - Have: " + fmt.Sprintf("%d", objUnderTest.km.KeyAndSignature.Key.KeySize.InBits()))
	}

	if !bytes.Equal(objUnderTest.km.KeyAndSignature.Key.Data, objUnderTest.kmpubkey.Data) {
		_, err = e.WriteString("Key given and key set are not equal")
	}
	if err != nil {
		return false, err
	}
	if e.String() != "" {
		return false, fmt.Errorf("%s", e.String())
	}
	return true, nil
}

// KMStructureValidSignatureSigSchemeCheck defines the behavior for the Test "KM Signature Scheme"
func KMStructureValidSignatureSigSchemeCheck() (bool, error) {
	var e strings.Builder
	var err error
	km := objUnderTest.km
	k := objUnderTest.kmpubkey

	if km.KeyAndSignature.Key.KeyAlg == manifest.AlgRSA && km.KeyAndSignature.Signature.SigScheme != manifest.AlgRSASSA {
		_, err = e.WriteString("SigScheme invalid for key set. Key is of type RSA but SigScheme is not RSASSA")
	}

	if km.KeyAndSignature.Signature.SigScheme == manifest.AlgRSASSA && km.KeyAndSignature.Key.KeyAlg != manifest.AlgRSA {
		_, err = e.WriteString("Set Key is invalid for SigScheme set. SigScheme is RSASSA but key is not of type RSA")
	}

	if k.KeyAlg == manifest.AlgRSA && km.KeyAndSignature.Signature.SigScheme != manifest.AlgRSASSA {
		_, err = e.WriteString("SigScheme invalid for key given. Key is of type RSA but SigScheme is not RSASSA")
	}

	if km.KeyAndSignature.Signature.SigScheme == manifest.AlgRSASSA && k.KeyAlg != manifest.AlgRSA {
		_, err = e.WriteString("Given Key is invalid for SigScheme set. SigScheme is RSASSA but key is not of type RSA")
	}

	if km.KeyAndSignature.Key.KeyAlg == manifest.AlgECDSA && km.KeyAndSignature.Signature.SigScheme != manifest.AlgECDSA {
		_, err = e.WriteString("SigScheme invalid for key set. Key is of type ECDSA but SigScheme is not ECDSA")
	}

	if km.KeyAndSignature.Signature.SigScheme == manifest.AlgECDSA && km.KeyAndSignature.Key.KeyAlg != manifest.AlgECDSA {
		_, err = e.WriteString("Set Key is invalid for SigScheme set. SigScheme is ECDSA but key is not of type ECDSA")
	}

	if k.KeyAlg == manifest.AlgECDSA && km.KeyAndSignature.Signature.SigScheme != manifest.AlgECDSA {
		_, err = e.WriteString("SigScheme invalid for key given. Key is of type ECDSA but SigScheme is not ECDSA")
	}

	if km.KeyAndSignature.Signature.SigScheme == manifest.AlgECDSA && k.KeyAlg != manifest.AlgECDSA {
		_, err = e.WriteString("Given Key is invalid for SigScheme set. SigScheme is ECDSA but key is not of type ECDSA")
	}

	if km.KeyAndSignature.Key.KeyAlg == manifest.AlgSM2 && km.KeyAndSignature.Signature.SigScheme != manifest.AlgSM2 {
		_, err = e.WriteString("SigScheme invalid for key set. Key is of type SM2 but SigScheme is not SM2")
	}

	if km.KeyAndSignature.Signature.SigScheme == manifest.AlgECDSA && km.KeyAndSignature.Key.KeyAlg != manifest.AlgECDSA {
		_, err = e.WriteString("Set Key is invalid for SigScheme set. SigScheme is SM2 but key is not of type SM2")
	}

	if k.KeyAlg == manifest.AlgECDSA && km.KeyAndSignature.Signature.SigScheme != manifest.AlgECDSA {
		_, err = e.WriteString("SigScheme invalid for key given. Key is of type SM2 but SigScheme is not SM2")
	}

	if km.KeyAndSignature.Signature.SigScheme == manifest.AlgECDSA && k.KeyAlg != manifest.AlgECDSA {
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

// KMStructureValidSigKeySize defines the behavior for the Test "KM Signature Keysize"
func KMStructureValidSigKeySize() (bool, error) {
	if objUnderTest.km.KeyAndSignature.Signature.KeySize.InBits() != objUnderTest.km.KeyAndSignature.Key.KeySize.InBits() {
		return false, fmt.Errorf("KM Signature Key size invalid compared to the set key. Have: %d Byte - Want: %d Byte", objUnderTest.km.KeyAndSignature.Signature.KeySize.InBits(), objUnderTest.km.KeyAndSignature.Key.KeySize.InBits())
	}
	return true, nil
}

// KMStructureValidSigHashAlg defines the behavior for the Test "KM Signature Hash Alg"
func KMStructureValidSigHashAlg() (bool, error) {
	k, err := objUnderTest.km.KeyAndSignature.Key.PubKey()
	if err != nil {
		return false, err
	}
	switch k.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		if objUnderTest.km.KeyAndSignature.Signature.HashAlg != manifest.AlgSHA256 && objUnderTest.km.KeyAndSignature.Signature.HashAlg != manifest.AlgSHA384 {
			return false, fmt.Errorf("KM Signature Key is RSA or ECDSA. Hash algorithm invalid. Must be SHA256 or SHA384. Have: %v", objUnderTest.km.KeyAndSignature.Signature.HashAlg.String())
		}
	case *sm2.PublicKey:
		if objUnderTest.km.KeyAndSignature.Signature.HashAlg != manifest.AlgSM3 {
			return false, fmt.Errorf("KM Signature Key is SM2. Hash algorithm invalid. Must be SM3_256. Have: %v", objUnderTest.km.KeyAndSignature.Signature.HashAlg.String())
		}
	default:
		return false, fmt.Errorf("Unknown Signature Key set")
	}
	return true, nil
}

// KMStructureValidSigData defines the behavior for the Test "KM Signature Data"
func KMStructureValidSigData() (bool, error) {
	k := objUnderTest.kmpubkey
	ft, err := fit.GetTable(objUnderTest.image)
	if err != nil {
		return false, err
	}
	var fitkm fit.EntryHeaders
	for _, item := range ft {
		if item.Type() == fit.EntryTypeKeyManifestRecord {
			fitkm = item
		}
	}
	kmoffset, err := tools.CalcImageOffset(objUnderTest.image, fitkm.Address.Pointer())
	if err != nil {
		return false, err
	}
	ksoffaddr := kmoffset + 12                                           // 12 bytes offset to KeySigOffsetBytes
	keySigOffsetByte := make([]byte, 2)                                  // KeySigOffset is two bytes in length
	copy(keySigOffsetByte[:], objUnderTest.image[ksoffaddr:ksoffaddr+2]) // copy KeySigOffset value
	r := bytes.NewReader(keySigOffsetByte)
	var kSoffSetValue uint16
	if err := binary.Read(r, binary.LittleEndian, &kSoffSetValue); err != nil { // Parse 2 bytes into uint16
		return false, err
	}
	kmdata := make([]byte, kSoffSetValue)                                        // KeySignatureOffsetValue also indicates the size of bytes to read for hash computation
	copy(kmdata[:], objUnderTest.image[kmoffset:kmoffset+uint64(kSoffSetValue)]) // copy the km data for hash computation
	pkey, err := k.PubKey()                                                      // Get the public key for verifying?
	if err != nil {
		return false, err
	}
	if err := validateSignature(&objUnderTest.km.KeyAndSignature.Signature, kmdata, pkey); err != nil { // Verify!!!
		return false, err
	}
	return true, nil
}
