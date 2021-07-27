// Copyright 2012-2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !arm,!arm64

package hwapi

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

var memPaths = [...]string{"/dev/fmem", "/dev/mem"}

func pathRead(path string, addr int64, data UintN) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(addr, io.SeekCurrent); err != nil {
		return err
	}
	return binary.Read(f, binary.BigEndian, data)
}

func selectDevMem() (string, error) {
	if len(memPaths) == 0 {
		return "", fmt.Errorf("Internal error: no /dev/mem device specified")
	}

	for _, p := range memPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("No suitable /dev/mem device found. Tried %#v", memPaths)
}

// ReadPhys reads data from physical memory at address addr. On x86 platforms,
// this uses the seek+read syscalls.
func (t TxtAPI) ReadPhys(addr int64, data UintN) error {
	devMem, err := selectDevMem()
	if err != nil {
		return err
	}

	return pathRead(devMem, addr, data)
}

// ReadPhysBuf reads data from physical memory at address addr. On x86 platforms,
// this uses the seek+read syscalls.
func (t TxtAPI) ReadPhysBuf(addr int64, buf []byte) error {
	devMem, err := selectDevMem()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(devMem, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(addr, io.SeekCurrent); err != nil {
		return err
	}
	return binary.Read(f, binary.BigEndian, buf)
}

func pathWrite(path string, addr int64, data UintN) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(addr, io.SeekCurrent); err != nil {
		return err
	}
	return binary.Write(f, binary.BigEndian, data)
}

// WritePhys writes data to physical memory at address addr. On x86 platforms, this
// uses the seek+read syscalls.
func (t TxtAPI) WritePhys(addr int64, data UintN) error {
	devMem, err := selectDevMem()
	if err != nil {
		return err
	}

	return pathWrite(devMem, addr, data)
}
