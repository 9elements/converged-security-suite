package tpmeventlog

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/9elements/converged-security-suite/v2/pkg/bootflow/subsystems/trustchains/tpm/pcr"
	pkgbytes "github.com/linuxboot/fiano/pkg/bytes"
	"github.com/linuxboot/fiano/pkg/guid"
)

// ptr copies a value and returns a pointer to the copy.
func ptr[T any](v T) *T {
	return &v
}

const (
	// PhysAddrBase is the physical address where the BIOS region is mapped to (downwards).
	PhysAddrBase = 0x100000000
)

type EventDataParserFunc func(ev *Event, imageSize uint64) (*EventDataParsed, error)

var eventDataParsers = map[pcr.ID]map[EventType]EventDataParserFunc{
	0: {
		EV_NO_ACTION: func(ev *Event, imageSize uint64) (*EventDataParsed, error) {
			locality, err := ParseLocality(ev.Data)
			if err != nil {
				return nil, err
			}
			return &EventDataParsed{TPMInitLocality: ptr(locality)}, nil
		},
		EV_POST_CODE:                   parseEventDataPCR0PostCode,
		EV_EFI_PLATFORM_FIRMWARE_BLOB2: parseEventDataPCR0PlatformFirmwareBlob2,
	},
}

func RegisterEventDataParser(pcrIndex pcr.ID, eventType EventType, fn EventDataParserFunc) {
	if eventDataParsers[pcrIndex] == nil {
		eventDataParsers[pcrIndex] = map[EventType]EventDataParserFunc{}
	}
	eventDataParsers[pcrIndex][eventType] = fn
}

type EventDataParsed struct {
	pkgbytes.Ranges
	TPMInitLocality *uint8
	Description     *string
	FvGUIDs         []guid.GUID
}

func (p *EventDataParsed) parseDescription() {
	if p.Description == nil {
		return
	}
	description := *p.Description
	switch {
	case strings.HasPrefix(description, "Fv(") &&
		strings.HasSuffix(description, ")") &&
		len(description) == len(guid.GUID{}.String())+len("Fv()"):
		guidString := description[len("Fv(") : len(description)-len(")")]
		guid, err := guid.Parse(guidString)
		if err == nil {
			p.FvGUIDs = append(p.FvGUIDs, *guid)
		}
	}
}

func isPhysAddr(addr, imageSize uint64) bool {
	return addr >= (PhysAddrBase-imageSize) && addr < PhysAddrBase
}

func ParseEventData(
	ev *Event,
	imageSize uint64,
) (*EventDataParsed, error) {
	m, ok := eventDataParsers[ev.PCRIndex]
	if !ok {
		return nil, fmt.Errorf("PCR%d is not supported, yet", ev.PCRIndex)
	}
	fn, ok := m[ev.Type]
	if !ok {
		return nil, fmt.Errorf("event type '%s' is not supported in PCR0, yet", ev.Type)
	}
	return fn(ev, imageSize)
}

func parseEventDataPCR0PostCode(
	ev *Event,
	imageSize uint64,
) (*EventDataParsed, error) {
	return parseEventDataPCR0PlatformFirmwareBlob2(ev, imageSize)
}

func parseEventDataPCR0PlatformFirmwareBlob2(
	ev *Event,
	imageSize uint64,
) (*EventDataParsed, error) {
	var result EventDataParsed

	isValidOffset := func(offset uint64) bool {
		return isPhysAddr(offset, imageSize)
	}
	isValidLength := func(length uint64) bool {
		return length <= imageSize
	}

	eventData := ev.Data
	// An example of Event Data:
	//
	// 00000000  12 46 56 5f 42 42 5f 41  46 54 45 52 5f 4d 45 4d  |.FV_BB_AFTER_MEM|
	// 00000010  4f 52 59 00 00 ac ff 00  00 00 00 00 00 07 00 00  |ORY.............|
	// 00000020  00 00 00                                          |...|
	//
	// We just need to parse these last 64bit integers. We do not know
	// if there could be multiple of them, but assuming there could.
	//
	// Also from common sense assuming that those are offset and length.
	for len(eventData) >= 16 {
		offset := binary.LittleEndian.Uint64(eventData[len(eventData)-8:])
		length := binary.LittleEndian.Uint64(eventData[len(eventData)-16:])
		// we do not know if offset always goes before length (or the opposite),
		// so we adapt:
		if !isValidLength(length) || !isValidOffset(offset) {
			// length bigger than the image does not make sense, assuming
			// just the order is wrong:
			offset, length = length, offset
		}
		if !isValidLength(length) || !isValidOffset(offset) {
			// looks like this is not length/offset at all
			break
		}
		eventData = eventData[:len(eventData)-16]
		result.Ranges = append(result.Ranges, pkgbytes.Range{
			Offset: offset,
			Length: length,
		})
	}

	if len(eventData) == 0 {
		return &result, nil
	}

	if int(eventData[0]) == len(eventData[1:]) {
		result.Description = ptr(string(eventData[1:]))
		result.parseDescription()
	}

	return &result, nil
}
