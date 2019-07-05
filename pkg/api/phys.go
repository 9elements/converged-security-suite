// Copyright 2012-2019 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !arm,!arm64

package api

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/u-root/u-root/pkg/ubinary"
)

const memPath = "/dev/mem"

// UintN is a wrapper around uint types and provides a few io-related
// functions.
type UintN interface {
	// Return size in bytes.
	Size() int64

	// Return string formatted in hex.
	String() string

	// Read from given address with native endianess.
	read(addr unsafe.Pointer) error

	// Write to given address with native endianess.
	write(addr unsafe.Pointer) error
}

// Uint8 is a wrapper around uint8.
type Uint8 uint8

// Uint16 is a wrapper around uint16.
type Uint16 uint16

// Uint32 is a wrapper around uint32.
type Uint32 uint32

// Uint64 is a wrapper around uint64.
type Uint64 uint64

// Size of uint8 is 1.
func (u *Uint8) Size() int64 {
	return 1
}

// Size of uint16 is 2.
func (u *Uint16) Size() int64 {
	return 2
}

// Size of uint32 is 4.
func (u *Uint32) Size() int64 {
	return 4
}

// Size of uint64 is 8.
func (u *Uint64) Size() int64 {
	return 8
}

// String formats a uint8 in hex.
func (u *Uint8) String() string {
	return fmt.Sprintf("%#02x", *u)
}

// String formats a uint16 in hex.
func (u *Uint16) String() string {
	return fmt.Sprintf("%#04x", *u)
}

// String formats a uint32 in hex.
func (u *Uint32) String() string {
	return fmt.Sprintf("%#08x", *u)
}

// String formats a uint64 in hex.
func (u *Uint64) String() string {
	return fmt.Sprintf("%#016x", *u)
}

func (u *Uint8) read(addr unsafe.Pointer) error {
	*u = Uint8(*(*uint8)(addr)) // TODO: rewrite in Go assembly for ARM
	return nil                  // TODO: catch misalign, segfault, sigbus, ...
}

func (u *Uint16) read(addr unsafe.Pointer) error {
	*u = Uint16(*(*uint16)(addr)) // TODO: rewrite in Go assembly for ARM
	return nil                    // TODO: catch misalign, segfault, sigbus, ...
}

func (u *Uint32) read(addr unsafe.Pointer) error {
	*u = Uint32(*(*uint32)(addr)) // TODO: rewrite in Go assembly for ARM
	return nil                    // TODO: catch misalign, segfault, sigbus, ...
}

func (u *Uint64) read(addr unsafe.Pointer) error {
	// Warning: On arm, this uses two ldr's rather than ldrd.
	*u = Uint64(*(*uint64)(addr)) // TODO: rewrite in Go assembly for ARM
	return nil                    // TODO: catch misalign, segfault, sigbus, ...
}

func (u *Uint8) write(addr unsafe.Pointer) error {
	*(*uint8)(addr) = uint8(*u) // TODO: rewrite in Go assembly for ARM
	return nil                  // TODO: catch misalign, segfault, sigbus, ...
}

func (u *Uint16) write(addr unsafe.Pointer) error {
	*(*uint16)(addr) = uint16(*u) // TODO: rewrite in Go assembly for ARM
	return nil                    // TODO: catch misalign, segfault, sigbus, ...
}

func (u *Uint32) write(addr unsafe.Pointer) error {
	*(*uint32)(addr) = uint32(*u) // TODO: rewrite in Go assembly for ARM
	return nil                    // TODO: catch misalign, segfault, sigbus, ...
}

func (u *Uint64) write(addr unsafe.Pointer) error {
	// Warning: On arm, this uses two str's rather than strd.
	*(*uint64)(addr) = uint64(*u) // TODO: rewrite in Go assembly for ARM
	return nil                    // TODO: catch misalign, segfault, sigbus, ...
}

func pathRead(path string, addr int64, data UintN) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(addr, io.SeekCurrent); err != nil {
		return err
	}
	return binary.Read(f, ubinary.NativeEndian, data)
}

// Read reads data from physical memory at address addr. On x86 platforms,
// this uses the seek+read syscalls. On arm platforms, this uses mmap.
func ReadPhys(addr int64, data UintN) error {
	return pathRead(memPath, addr, data)
}

func ReadPhysBuf(addr int64, buf []byte) error {
	var b Uint8

	for i := 0; i < len(buf); i += 1 {
		err := ReadPhys(int64(i)+addr, &b)
		if err != nil {
			return err
		}
		buf[i] = byte(b)
	}

	return nil
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
	return binary.Write(f, ubinary.NativeEndian, data)
}

// Write writes data to physical memory at address addr. On x86 platforms, this
// uses the seek+read syscalls. On arm platforms, this uses mmap.
func WritePhys(addr int64, data UintN) error {
	return pathWrite(memPath, addr, data)
}
