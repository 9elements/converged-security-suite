package dmidecode

import (
	"github.com/xaionaro-facebook/go-dmidecode"
)

type BIOSInfo struct {
	Vendor      string
	Version     string
	ReleaseDate string
	Revision    string
}

func (dmit *DMITable) BIOSInfo() BIOSInfo {
	return BIOSInfo{
		Vendor:      dmit.Query(dmidecode.KeywordBIOSVendor),
		Version:     dmit.Query(dmidecode.KeywordBIOSVersion),
		ReleaseDate: dmit.Query(dmidecode.KeywordBIOSReleaseDate),
		Revision:    dmit.Query(dmidecode.KeywordBIOSRevision),
	}
}
