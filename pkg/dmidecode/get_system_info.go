package dmidecode

import (
	"github.com/xaionaro-facebook/go-dmidecode"
)

type SystemInfo struct {
	SystemManufacturer string
	SystemProductName  string
	SystemVersion      string
	SystemSerialNumber string
	SystemUUID         string
	SystemFamily       string
}

func (dmit *DMITable) SystemInfo() SystemInfo {
	return SystemInfo{
		SystemManufacturer: dmit.Query(dmidecode.KeywordSystemManufacturer),
		SystemProductName:  dmit.Query(dmidecode.KeywordSystemProductName),
		SystemVersion:      dmit.Query(dmidecode.KeywordSystemVersion),
		SystemSerialNumber: dmit.Query(dmidecode.KeywordSystemSerialNumber),
		SystemUUID:         dmit.Query(dmidecode.KeywordSystemUUID),
		SystemFamily:       dmit.Query(dmidecode.KeywordSystemFamily),
	}
}
