package api

import (
	"fmt"
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

			f, err := os.Open(path)
			if err != nil {
				continue
			}

			var type_buf [len(reservedKeyword) + 1]byte
			l, err := f.Read(type_buf[:])
			if l != len(reservedKeyword) {
				continue
			}

			if string(type_buf[:len(reservedKeyword)]) == reservedKeyword {
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

const hexStringLength = 12 // 32 bit hex string with 0x prefix plus newline, plus one

func readHexInteger(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}

	var start_buf [hexStringLength]byte
	l, err := f.Read(start_buf[:])
	if l == hexStringLength {
		return 0, err
	}

	this_start, err := strconv.ParseUint(string(start_buf[:l-1]), 0, 64)
	if err != nil {
		return 0, err
	} else {
		return this_start, nil
	}
}
