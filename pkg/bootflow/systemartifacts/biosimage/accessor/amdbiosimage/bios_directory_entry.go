package amdbiosimage

import (
	"fmt"
	"sort"

	"github.com/linuxboot/fiano/pkg/amd/manifest"
)

type DirectoryLevel int

const (
	DirectoryLevelAll = DirectoryLevel(iota)
	DirectoryLevelL1
	DirectoryLevelL2
)

func (l DirectoryLevel) String() string {
	switch l {
	case DirectoryLevelAll:
		return "L1-and-L2"
	case DirectoryLevelL1:
		return "L1"
	case DirectoryLevelL2:
		return "L2"
	}
	return fmt.Sprintf("unknown_value_%d", int(l))
}

func (a *Accessor) BIOSDirectoryEntries(level DirectoryLevel, entryTypes ...manifest.BIOSDirectoryTableEntryType) ([]manifest.BIOSDirectoryTableEntry, error) {
	return a.biosDirectoryEntries(func(l DirectoryLevel, bte *manifest.BIOSDirectoryTableEntry) bool {
		if level != DirectoryLevelAll && level != l {
			return false
		}
		for _, entryType := range entryTypes {
			if bte.Type == entryType {
				return true
			}
		}
		return false
	})
}

func (a *Accessor) biosDirectoryEntries(
	passFilter func(DirectoryLevel, *manifest.BIOSDirectoryTableEntry) bool,
) ([]manifest.BIOSDirectoryTableEntry, error) {
	amdFW, err := a.AMDFirmware()
	if err != nil {
		return nil, fmt.Errorf("unable to get AMD firmware: %w", err)
	}
	pspFW := amdFW.PSPFirmware()

	var result []manifest.BIOSDirectoryTableEntry
	type directory struct {
		Level     DirectoryLevel
		Directory *manifest.BIOSDirectoryTable
	}
	for _, biosDirectory := range []directory{
		{Level: DirectoryLevelL2, Directory: pspFW.BIOSDirectoryLevel2},
		{Level: DirectoryLevelL1, Directory: pspFW.BIOSDirectoryLevel1},
	} {
		if biosDirectory.Directory == nil {
			continue
		}
		for _, entry := range biosDirectory.Directory.Entries {
			if passFilter(biosDirectory.Level, &entry) {
				result = append(result, entry)
			}
		}
		break
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Instance < result[j].Instance
	})
	return result, nil
}
