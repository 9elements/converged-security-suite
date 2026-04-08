package intelsteps

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/dataconverters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtpublic"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/9elements/converged-security-suite/v2/pkg/tpmeventlog"
	"github.com/google/go-tpm/legacy/tpm2"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	manifest "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
	bootpolicy "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/bootpolicy"
	key "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt/keymanifest"
)

// MeasurePCR0DATA is a types.Step to measure the PCR0_DATA structure.
type MeasurePCR0DATA struct{}

var _ types.Step = (*MeasurePCR0DATA)(nil)

func (MeasurePCR0DATA) Actions(ctx context.Context, s *types.State) types.Actions {
	intelFW, err := intelbiosimage.Get(ctx, s)
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to get Intel-specific data accessor for the given BIOS firmware image: %w", err)),
		}
	}

	txtRegisters, err := txtpublic.Get(s)
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to get TXT registers: %w", err)),
		}
	}

	var pcr0DATA pcr0DATA
	pcr0DATA.acmPolicyStatus = types.Reference{
		Artifact: txtRegisters,
		MappedRanges: types.MappedRanges{
			AddressMapper: nil,
			Ranges: []pkgbytes.Range{{
				Offset: registers.ACMPolicyStatus(0).Address() - registers.TxtPublicSpace,
				Length: uint64(registers.ACMPolicyStatus(0).BitSize() / 8),
			}},
		},
	}

	acmEntry, acmFIT, err := intelFW.ACM()
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to get ACM: %w", err)),
		}
	}

	acmAddr := acmFIT.GetEntryBase().Headers.Address.Pointer()

	// From Intel CBnT doc: "SVN field of ACM header (offset 28) indicates..."
	// Offset 28 == TxtSVN
	pcr0DATA.acmHeaderSVN = types.Reference{
		Artifact: intelFW.SystemArtifact(),
		MappedRanges: types.MappedRanges{
			AddressMapper: biosimage.PhysMemMapper{},
			Ranges: []pkgbytes.Range{{
				Offset: acmAddr + acmEntry.GetCommon().TXTSVNBinaryOffset(),
				Length: uint64(binary.Size(acmEntry.GetTXTSVN())),
			}},
		},
	}
	pcr0DATA.acmSignature = types.Reference{
		Artifact: intelFW.SystemArtifact(),
		MappedRanges: types.MappedRanges{
			AddressMapper: biosimage.PhysMemMapper{},
			Ranges: []pkgbytes.Range{{
				Offset: acmAddr + acmEntry.RSASigBinaryOffset(),
				Length: uint64(len(acmEntry.GetRSASig())),
			}},
		},
	}

	keyManifest, keyManifestFITEntry, err := intelFW.KeyManifest()
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to get key manifest: %w", err)),
		}
	}
	kmAddr := keyManifestFITEntry.Headers.Address.Pointer()
	switch km := (*keyManifest).(type) {
	case *key.BGManifest:
		keyAndSignatureOffset, err := km.OffsetOf(5)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get BG key manifest key-and-signature offset: %w", err))}
		}
		signatureOffset, err := km.KeyAndSignature.OffsetOf(2)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get BG key manifest signature offset: %w", err))}
		}
		signatureDataOffset, err := km.KeyAndSignature.Signature.OffsetOf(4)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get BG key manifest signature data offset: %w", err))}
		}
		pcr0DATA.kmSignature = types.Reference{
			Artifact: intelFW.SystemArtifact(),
			MappedRanges: types.MappedRanges{
				AddressMapper: biosimage.PhysMemMapper{},
				Ranges: []pkgbytes.Range{{
					Offset: kmAddr + keyAndSignatureOffset + signatureOffset + signatureDataOffset,
					Length: uint64(len(km.KeyAndSignature.Signature.Data)),
				}},
			},
		}
	case *key.CBnTManifest:
		keyAndSignatureOffset, err := km.OffsetOf(8)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get CBnT key manifest key-and-signature offset: %w", err))}
		}
		signatureOffset, err := km.KeyAndSignature.OffsetOf(2)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get CBnT key manifest signature offset: %w", err))}
		}
		signatureDataOffset, err := km.KeyAndSignature.Signature.OffsetOf(4)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get CBnT key manifest signature data offset: %w", err))}
		}
		pcr0DATA.kmSignature = types.Reference{
			Artifact: intelFW.SystemArtifact(),
			MappedRanges: types.MappedRanges{
				AddressMapper: biosimage.PhysMemMapper{},
				Ranges: []pkgbytes.Range{{
					Offset: kmAddr + keyAndSignatureOffset + signatureOffset + signatureDataOffset,
					Length: uint64(len(km.KeyAndSignature.Signature.Data)),
				}},
			},
		}
	default:
		return types.Actions{commonactions.Panic(fmt.Errorf("unsupported key manifest type: %T", km))}
	}

	bpManifest, bpManifestFITEntry, err := intelFW.BootPolicyManifest()
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to get boot policy manifest: %w", err)),
		}
	}
	bpmAddr := bpManifestFITEntry.Headers.Address.Pointer()
	var (
		ibbdigests         []manifest.HashStructure
		firstDigestOffset  uint64
		bpmSignatureOffset uint64
		bpmSignatureLength uint64
	)
	switch bpm := (*bpManifest).(type) {
	case *bootpolicy.ManifestBG:
		pmseOffset, err := bpm.OffsetOf(3)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get BG boot policy manifest PMSE offset: %w", err))}
		}
		keySignatureOffset, err := bpm.PMSE.OffsetOf(1)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get BG boot policy manifest key signature offset: %w", err))}
		}
		signatureOffset, err := bpm.PMSE.KeySignature.OffsetOf(2)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get BG boot policy manifest signature offset: %w", err))}
		}
		signatureDataOffset, err := bpm.PMSE.Signature.OffsetOf(4)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get BG boot policy manifest signature data offset: %w", err))}
		}
		bpmSignatureOffset = pmseOffset + keySignatureOffset + signatureOffset + signatureDataOffset
		bpmSignatureLength = uint64(len(bpm.PMSE.Signature.Data))

		if len(bpm.SE) == 0 {
			return types.Actions{commonactions.Panic(fmt.Errorf("IBBDigest list is empty"))}
		}
		seOffset, err := bpm.OffsetOf(1)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get BG boot policy manifest SE offset: %w", err))}
		}
		digestOffset, err := bpm.SE[0].OffsetOf(13)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get BG boot policy manifest digest offset: %w", err))}
		}
		ibbdigests = []manifest.HashStructure{bpm.SE[0].Digest}
		firstDigestOffset = seOffset + digestOffset
	case *bootpolicy.ManifestCBnT:
		pmseOffset, err := bpm.OffsetOf(6)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get CBnT boot policy manifest PMSE offset: %w", err))}
		}
		keySignatureOffset, err := bpm.PMSE.OffsetOf(1)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get CBnT boot policy manifest key signature offset: %w", err))}
		}
		signatureOffset, err := bpm.PMSE.KeySignature.OffsetOf(2)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get CBnT boot policy manifest signature offset: %w", err))}
		}
		signatureDataOffset, err := bpm.PMSE.Signature.OffsetOf(4)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get CBnT boot policy manifest signature data offset: %w", err))}
		}
		bpmSignatureOffset = pmseOffset + keySignatureOffset + signatureOffset + signatureDataOffset
		bpmSignatureLength = uint64(len(bpm.PMSE.Signature.Data))

		if len(bpm.SE) == 0 {
			return types.Actions{commonactions.Panic(fmt.Errorf("IBBDigest list is empty"))}
		}
		seOffset, err := bpm.OffsetOf(1)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get CBnT boot policy manifest SE offset: %w", err))}
		}
		digestListOffset, err := bpm.SE[0].OffsetOf(14)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get CBnT boot policy manifest digest-list offset: %w", err))}
		}
		digestArrayOffset, err := bpm.SE[0].DigestList.OffsetOf(1)
		if err != nil {
			return types.Actions{commonactions.Panic(fmt.Errorf("unable to get CBnT boot policy manifest digest-list array offset: %w", err))}
		}
		ibbdigests = bpm.SE[0].DigestList.List
		// +2 skips the digest-list element count prefix (uint16) to point to the first digest.
		firstDigestOffset = seOffset + digestListOffset + digestArrayOffset + 2
	default:
		return types.Actions{commonactions.Panic(fmt.Errorf("unsupported boot policy manifest type: %T", bpm))}
	}
	pcr0DATA.bpmSignature = types.Reference{
		Artifact: intelFW.SystemArtifact(),
		MappedRanges: types.MappedRanges{
			AddressMapper: biosimage.PhysMemMapper{},
			Ranges: []pkgbytes.Range{{
				Offset: bpmAddr + bpmSignatureOffset,
				Length: bpmSignatureLength,
			}},
		},
	}
	if len(ibbdigests) == 0 {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("IBBDigest list is empty")),
		}
	}

	var actions types.Actions
	for _, hashAlgo := range []manifest.Algorithm{
		manifest.AlgSHA1,
		manifest.AlgSHA256,
	} {
		pcr0DATA.hashAlgo = hashAlgo
		// find ibbDigest with the required algorithm
		offsetToCurrentDigest := firstDigestOffset
		var found bool
		for idx := range ibbdigests {
			if ibbdigests[idx].HashAlg == hashAlgo {
				hashBufferOffset, err := ibbdigests[idx].OffsetOf(1)
				if err != nil {
					actions = append(actions, commonactions.Panic(fmt.Errorf("unable to get IBB digest hash buffer offset: %w", err)))
					break
				}
				pcr0DATA.ibbDigest = types.Reference{
					Artifact: intelFW.SystemArtifact(),
					MappedRanges: types.MappedRanges{
						AddressMapper: biosimage.PhysMemMapper{},
						Ranges: []pkgbytes.Range{{
							// +2 skips the HashBuffer size prefix (uint16).
							Offset: bpmAddr + offsetToCurrentDigest + hashBufferOffset + 2,
							Length: uint64(len(ibbdigests[idx].HashBuffer)),
						}},
					},
				}
				found = true
				break
			}
			offsetToCurrentDigest += ibbdigests[idx].TotalSize()
		}

		if found {
			actions = append(actions, pcr0DATA.compileActions()...)
		} else {
			actions = append(
				actions,
				commonactions.Panic(fmt.Errorf("no IBBDigest with hash algorithm: %v", hashAlgo)),
			)
		}
	}
	return actions
}

type pcr0DATA struct {
	hashAlgo        manifest.Algorithm
	acmPolicyStatus types.Reference
	acmHeaderSVN    types.Reference
	acmSignature    types.Reference
	kmSignature     types.Reference
	bpmSignature    types.Reference
	ibbDigest       types.Reference
}

// Measurement returns pcr0DATA as a Measurement.
func (d pcr0DATA) compileActions() types.Actions {
	h, err := d.hashAlgo.Hash()
	if err != nil {
		panic(fmt.Errorf("d.hashAlgo.Hash() return an error: should never happen: %w", err))
	}
	data := types.NewData(types.References{
		d.acmPolicyStatus,
		d.acmHeaderSVN,
		d.acmSignature,
		d.kmSignature,
		d.bpmSignature,
		d.ibbDigest,
	})
	data.Converter = dataconverters.NewHasher(h)
	return types.Actions{
		tpmactions.NewTPMExtend(pcr.ID(0), (*datasources.StaticData)(data), tpm2.Algorithm(d.hashAlgo)),
		tpmactions.NewTPMEventLogAdd(pcr.ID(0), tpm2.Algorithm(d.hashAlgo), data.ConvertedBytes(), tpmeventlog.EV_S_CRTM_CONTENTS, []byte("PCR0_DATA "+d.hashAlgo.String())),
	}
}
