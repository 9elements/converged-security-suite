package api

const txtPublicSpace = 0xFED30000

type TXTStatus struct {
	SenterDone bool // SENTER.DONE.STS (0)
	SexitDone  bool // SEXIT.DONE.STS (1)
	// Reserved (2-5)
	MemConfigLock bool // MEM-CONFIG-LOCK (6)
	PrivateOpen   bool // PRIVATE-OPEN.STS (7)
	// Reserved (8-14)
	Locality1Open bool // TXT.LOCALITY1.OPEN.STS (15)
	Locality2Open bool // TXT.LOCALITY1.OPEN.STS (16)
	// Reserved (17-63)
}

type TXTErrorCode struct {
	ModuleType        uint8 // 0: BIOS ACM, 1: Intel TXT
	ClassCode         uint8
	MajorErrorCode    uint8
	SoftwareSource    bool // 0: ACM, 1: MLE
	MinorErrorCode    uint16
	Type1Reserved     uint8
	ProcessorSoftware bool
	ValidInvalid      bool
}

type DMAProtectedRange struct {
	Lock bool
	// Reserved 1-3
	Size uint8
	// Reserved 12-19
	Top uint16
}

type TXTRegisterSpace struct {
	Sts       TXTStatus         // TXT.STS (0x0)
	TxtReset  bool              // TXT.ESTS (0x8)
	ErrorCode TXTErrorCode      // TXT.ERRORCODE
	FsbIf     uint32            // TXT.VER.FSBIF
	Vid       uint16            // TXT.DIDVID.VID
	Did       uint16            // TXT.DIDVID.DID
	Rid       uint16            // TXT.DIDVID.RID
	IdExt     uint16            // TXT.DIDVID.ID-EXT
	QpiIf     uint32            // TXT.VER.QPIIF
	SinitBase uint32            // TXT.SINIT.BASE
	SinitSize uint32            // TXT.SINIT.SIZE
	MleJoin   uint32            // TXT.MLE.JOIN
	HeapBase  uint32            // TXT.HEAP.BASE
	HeapSize  uint32            // TXT.HEAP.SIZE
	Dpr       DMAProtectedRange // TXT.DPR
	PublicKey [4]uint64         // TXT.PUBLIC.KEY
	E2Sts     uint64            // TXT.E2STS
}

func ReadTXTRegs() (TXTRegisterSpace, error) {
	var regSpace TXTRegisterSpace
	var err error
	var u8 Uint8
	var u32 Uint32
	var u64 Uint64

	regSpace.Sts, err = readTXTStatus()
	if err != nil {
		return regSpace, err

	}

	regSpace.ErrorCode, err = readTXTErrorCode()
	if err != nil {
		return regSpace, err

	}

	regSpace.Dpr, err = readDMAProtectedRange()
	if err != nil {
		return regSpace, err

	}

	// TXT.ESTS (0x8)
	err = ReadPhys(txtPublicSpace+0x8, &u8)
	if err != nil {
		return regSpace, err
	}
	regSpace.TxtReset = u8&1 != 0

	// TXT.VER.FSBIF
	err = ReadPhys(txtPublicSpace+0x100, &u32)
	if err != nil {
		return regSpace, err
	}
	regSpace.FsbIf = uint32(u32)

	// TXT.DIDVID
	err = ReadPhys(txtPublicSpace+0x110, &u64)
	if err != nil {
		return regSpace, err
	}
	regSpace.Vid = uint16((u64 >> 0) & 0xffff)
	regSpace.Did = uint16((u64 >> 16) & 0xffff)
	regSpace.Rid = uint16((u64 >> 32) & 0xffff)
	regSpace.IdExt = uint16((u64 >> 48) & 0xffff)

	// TXT.VER.QPIIF
	err = ReadPhys(txtPublicSpace+0x200, &u32)
	if err != nil {
		return regSpace, err
	}
	regSpace.QpiIf = uint32(u32)

	// TXT.SINIT.BASE
	err = ReadPhys(txtPublicSpace+0x270, &u32)
	if err != nil {
		return regSpace, err
	}
	regSpace.SinitBase = uint32(u32)

	// TXT.SINIT.SIZE
	err = ReadPhys(txtPublicSpace+0x278, &u32)
	if err != nil {
		return regSpace, err
	}
	regSpace.SinitSize = uint32(u32)

	// TXT.MLE.JOIN
	err = ReadPhys(txtPublicSpace+0x290, &u32)
	if err != nil {
		return regSpace, err
	}
	regSpace.MleJoin = uint32(u32)

	// TXT.HEAP.BASE
	err = ReadPhys(txtPublicSpace+0x300, &u32)
	if err != nil {
		return regSpace, err
	}
	regSpace.HeapBase = uint32(u32)

	// TXT.HEAP.SIZE
	err = ReadPhys(txtPublicSpace+0x308, &u32)
	if err != nil {
		return regSpace, err
	}
	regSpace.HeapSize = uint32(u32)

	// TXT.PUBLIC.KEY
	for i := 0; i < 4; i++ {
		err = ReadPhys(txtPublicSpace+0x400+int64(i)*8, &u64)
		if err != nil {
			return regSpace, err
		}
		regSpace.PublicKey[i] = uint64(u64)
	}

	// TXT.E2STS
	err = ReadPhys(txtPublicSpace+0x8f0, &u64)
	if err != nil {
		return regSpace, err
	}
	regSpace.E2Sts = uint64(u64)

	return regSpace, nil
}

func readTXTStatus() (TXTStatus, error) {
	var ret TXTStatus
	var u64 Uint64
	err := ReadPhys(txtPublicSpace, &u64)

	if err != nil {
		return ret, err
	}

	ret.SenterDone = u64&(1<<0) != 0
	ret.SexitDone = u64&(1<<1) != 0
	ret.MemConfigLock = u64&(1<<6) != 0
	ret.PrivateOpen = u64&(1<<7) != 0
	ret.Locality1Open = u64&(1<<15) != 0
	ret.Locality2Open = u64&(1<<16) != 0

	return ret, nil
}

func readTXTErrorCode() (TXTErrorCode, error) {
	var ret TXTErrorCode
	var u32 Uint32
	err := ReadPhys(txtPublicSpace+0x30, &u32)

	if err != nil {
		return ret, err
	}

	ret.ModuleType = uint8((u32 >> 0) & 0x7)           // 3:0
	ret.ClassCode = uint8((u32 >> 4) & 0x3f)           // 9:4
	ret.MajorErrorCode = uint8((u32 >> 10) & 0x1f)     // 14:10
	ret.SoftwareSource = (u32>>15)&0x1 != 0            // 15
	ret.MinorErrorCode = uint16((u32 >> 16) & 0x3ffff) // 27:16
	ret.Type1Reserved = uint8((u32 >> 28) & 0x3)       // 29:28
	ret.ProcessorSoftware = (u32>>30)&0x1 != 0         // 30
	ret.ValidInvalid = (u32>>31)&0x1 != 0              // 31

	return ret, nil
}

func readDMAProtectedRange() (DMAProtectedRange, error) {
	var ret DMAProtectedRange
	var u32 Uint32
	err := ReadPhys(txtPublicSpace+0x330, &u32)

	if err != nil {
		return ret, err
	}

	ret.Lock = u32&1 != 0
	ret.Size = uint8((u32 >> 4) & 0xff)   // 11:4
	ret.Top = uint16((u32 >> 20) & 0xfff) // 31:20

	return ret, nil
}
