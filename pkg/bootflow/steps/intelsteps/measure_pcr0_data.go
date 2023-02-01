package intelsteps

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/commonactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/actions/tpmactions"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/dataconverters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/datasources"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/biosimage/accessor/intelbiosimage"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/systemartifacts/txtregisters"
	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/types"
	pcrtypes "github.com/9elements/converged-security-suite/v2/pkg/pcr/types"
	"github.com/9elements/converged-security-suite/v2/pkg/registers"
	"github.com/google/go-tpm/tpm2"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	manifest "github.com/linuxboot/fiano/pkg/intel/metadata/cbnt"
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

	txtRegisters, err := txtregisters.Get(s)
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to get TXT registers: %w", err)),
		}
	}

	var pcr0DATA pcr0DATA
	pcr0DATA.acmPolicyStatus = types.Reference{
		Artifact:      txtRegisters,
		AddressMapper: nil,
		Ranges: []pkgbytes.Range{{
			Offset: registers.ACMPolicyStatus(0).Address() - registers.TxtPublicSpace,
			Length: uint64(registers.ACMPolicyStatus(0).BitSize() / 8),
		}},
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
		Artifact:      intelFW.SystemArtifact(),
		AddressMapper: biosimage.PhysMemMapper{},
		Ranges: []pkgbytes.Range{{
			Offset: acmAddr + acmEntry.GetCommon().TXTSVNBinaryOffset(),
			Length: uint64(binary.Size(acmEntry.GetTXTSVN())),
		}},
	}
	pcr0DATA.acmSignature = types.Reference{
		Artifact:      intelFW.SystemArtifact(),
		AddressMapper: biosimage.PhysMemMapper{},
		Ranges: []pkgbytes.Range{{
			Offset: acmAddr + acmEntry.RSASigBinaryOffset(),
			Length: uint64(len(acmEntry.GetRSASig())),
		}},
	}

	keyManifest, keyManifestFITEntry, err := intelFW.KeyManifest()
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to get key manifest: %w", err)),
		}
	}
	kmAddr := keyManifestFITEntry.Headers.Address.Pointer()
	pcr0DATA.kmSignature = types.Reference{
		Artifact:      intelFW.SystemArtifact(),
		AddressMapper: biosimage.PhysMemMapper{},
		Ranges: []pkgbytes.Range{{
			Offset: kmAddr + keyManifest.KeyAndSignatureOffset() + keyManifest.KeyAndSignature.SignatureOffset() + keyManifest.KeyAndSignature.Signature.DataOffset(),
			Length: uint64(len(keyManifest.KeyAndSignature.Signature.Data)),
		}},
	}

	bpManifest, bpManifestFITEntry, err := intelFW.BootPolicyManifest()
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to get boot policy manifest: %w", err)),
		}
	}
	bpmAddr := bpManifestFITEntry.Headers.Address.Pointer()
	pcr0DATA.bpmSignature = types.Reference{
		Artifact:      intelFW.SystemArtifact(),
		AddressMapper: biosimage.PhysMemMapper{},
		Ranges: []pkgbytes.Range{{
			Offset: bpmAddr + uint64(bpManifest.KeySignatureOffset) + bpManifest.PMSE.SignatureOffset() + bpManifest.PMSE.Signature.DataOffset(),
			Length: uint64(len(bpManifest.PMSE.Signature.Data)),
		}},
	}
	uefi, err := intelFW.Image.Parse()
	if err != nil {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("unable to parse UEFI layout: %w", err)),
		}
	}
	ibbIsOK := bpManifest.ValidateIBB(uefi) == nil

	digests := bpManifest.SE[0].DigestList.List
	if len(digests) == 0 {
		return types.Actions{
			commonactions.Panic(fmt.Errorf("IBBDigest list is empty")),
		}
	}

	var actions types.Actions
	offsetToTheFirstDigest := bpmAddr + bpManifest.SEOffset() +
		bpManifest.SE[0].DigestListOffset() + (bpManifest.SE[0].DigestList.ListOffset() + 2)
	for _, hashAlgo := range []manifest.Algorithm{
		manifest.AlgSHA1,
		manifest.AlgSHA256,
	} {
		pcr0DATA.hashAlgo = hashAlgo
		pcr0DATA.ibbVerifiedRange = nil
		// Note: +2 - skip array size field to get the first element
		// find ibbDigest with the required algorithm
		offsetToCurrentDigest := offsetToTheFirstDigest
		var found bool
		for idx := range digests {
			if digests[idx].HashAlg == hashAlgo {
				pcr0DATA.ibbDigest = types.Reference{
					Artifact:      intelFW.SystemArtifact(),
					AddressMapper: biosimage.PhysMemMapper{},
					Ranges: []pkgbytes.Range{{
						Offset: offsetToCurrentDigest + (digests[idx].HashBufferOffset() + 2),
						Length: uint64(len(digests[idx].HashBuffer)),
					}},
				}
				found = true
				if idx == 0 && ibbIsOK {
					addrMapper := biosimage.PhysMemMapper{}
					ibbRanges := bpManifest.IBBDataRanges(intelFW.SystemArtifact().Size())
					ibbRanges = addrMapper.UnresolveFullImageOffset(intelFW.SystemArtifact(), ibbRanges...)
					pcr0DATA.ibbVerifiedRange = &types.Reference{
						Artifact:      intelFW.SystemArtifact(),
						AddressMapper: addrMapper,
						Ranges:        ibbRanges,
					}
				}
				break
			}
			offsetToCurrentDigest += digests[idx].TotalSize()
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
	hashAlgo         manifest.Algorithm
	acmPolicyStatus  types.Reference
	acmHeaderSVN     types.Reference
	acmSignature     types.Reference
	kmSignature      types.Reference
	bpmSignature     types.Reference
	ibbDigest        types.Reference
	ibbVerifiedRange *types.Reference
}

// Measurement returns pcr0DATA as a Measurement.
func (d pcr0DATA) compileActions() types.Actions {
	h, err := d.hashAlgo.Hash()
	if err != nil {
		panic(fmt.Errorf("d.hashAlgo.Hash() return an error: should never happen: %w", err))
	}
	data := types.Data{
		References: []types.Reference{
			d.acmPolicyStatus,
			d.acmHeaderSVN,
			d.acmSignature,
			d.kmSignature,
			d.bpmSignature,
			d.ibbDigest,
		},
		Converter: dataconverters.Hasher(h),
	}
	if d.ibbVerifiedRange != nil {
		data.IsAlsoMeasurementOf = append(data.IsAlsoMeasurementOf, *d.ibbVerifiedRange)
	}
	return types.Actions{
		tpmactions.NewTPMExtend(pcrtypes.ID(0), (*datasources.StaticData)(&data), tpm2.Algorithm(d.hashAlgo)),
		tpmactions.NewTPMEventLogAdd(pcrtypes.ID(0), tpm2.Algorithm(d.hashAlgo), data.Bytes(), []byte("PCR0_DATA "+d.hashAlgo.String())),
	}
}
