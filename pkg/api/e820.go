package api

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
)

const reservedKeyword = "Reserved\n"

// Reads the e820 table exported via /sys/firmware/memmap and checks whether
// the range [start; end] is marked as reserved. Returns true if it is reserved,
// false if not.
func IsReservedInE810(start uint64, end uint64) (bool, error) {
	if start > end {
		return false, fmt.Errorf("Invalid range")
	}

	dir, err := os.Open("/sys/firmware/memmap")
	if err != nil {
		return false, fmt.Errorf("Cannot access e820 table: %s", err)
	}

	subdirs, err := dir.Readdir(0)
	if err != nil {
		return false, fmt.Errorf("Cannot access e820 table: %s", err)
	}

	for _, subdir := range subdirs {
		if subdir.IsDir() {

			path := fmt.Sprintf("/sys/firmware/memmap/%s/type", subdir.Name())
			buf, err := ioutil.ReadFile(path)
			if err != nil {
				continue
			}

			if string(buf) == reservedKeyword {
				path := fmt.Sprintf("/sys/firmware/memmap/%s/start", subdir.Name())
				this_start, err := readHexInteger(path)
				if err != nil {
					continue
				}

				path = fmt.Sprintf("/sys/firmware/memmap/%s/end", subdir.Name())
				this_end, err := readHexInteger(path)
				if err != nil {
					continue
				}

				if this_start <= start && this_end >= end {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func readHexInteger(path string) (uint64, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}

	ret, err := strconv.ParseUint(string(buf), 0, 64)
	if err != nil {
		return 0, err
	} else {
		return ret, nil
	}
}
