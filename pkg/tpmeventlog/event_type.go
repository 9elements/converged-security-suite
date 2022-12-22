package tpmeventlog

import "fmt"

// EventType defines the kind of data reported by an Event.
//
// See also: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf#page=102
type EventType uint32

// The list of available EventLog entry types.
const (
	EV_PREBOOT_CERT                  = EventType(0x00000000)
	EV_POST_CODE                     = EventType(0x00000001)
	EV_UNUSED                        = EventType(0x00000002)
	EV_NO_ACTION                     = EventType(0x00000003)
	EV_SEPARATOR                     = EventType(0x00000004)
	EV_ACTION                        = EventType(0x00000005)
	EV_EVENT_TAG                     = EventType(0x00000006)
	EV_S_CRTM_CONTENTS               = EventType(0x00000007)
	EV_S_CRTM_VERSION                = EventType(0x00000008)
	EV_CPU_MICROCODE                 = EventType(0x00000009)
	EV_PLATFORM_CONFIG_FLAGS         = EventType(0x0000000A)
	EV_TABLE_OF_DEVICES              = EventType(0x0000000B)
	EV_COMPACT_HASH                  = EventType(0x0000000C)
	EV_IPL                           = EventType(0x0000000D)
	EV_IPL_PARTITION_DATA            = EventType(0x0000000E)
	EV_NONHOST_CODE                  = EventType(0x0000000F)
	EV_NONHOST_CONFIG                = EventType(0x00000010)
	EV_NONHOST_INFO                  = EventType(0x00000011)
	EV_OMIT_BOOT_DEVICE_EVENTS       = EventType(0x00000012)
	EV_EFI_EVENT_BASE                = EventType(0x80000000)
	EV_EFI_VARIABLE_DRIVER_CONFIG    = EventType(0x80000001)
	EV_EFI_VARIABLE_BOOT             = EventType(0x80000002)
	EV_EFI_BOOT_SERVICES_APPLICATION = EventType(0x80000003)
	EV_EFI_BOOT_SERVICES_DRIVER      = EventType(0x80000004)
	EV_EFI_RUNTIME_SERVICES_DRIVER   = EventType(0x80000005)
	EV_EFI_GPT_EVENT                 = EventType(0x80000006)
	EV_EFI_ACTION                    = EventType(0x80000007)
	EV_EFI_PLATFORM_FIRMWARE_BLOB    = EventType(0x80000008)
	EV_EFI_HANDOFF_TABLES            = EventType(0x80000009)
	EV_EFI_PLATFORM_FIRMWARE_BLOB2   = EventType(0x8000000A)
	EV_EFI_HCRTM_EVENT               = EventType(0x80000010)
	EV_EFI_VARIABLE_AUTHORITY        = EventType(0x800000E0)
)

// String implements fmt.Stringer
func (t EventType) String() string {
	return fmt.Sprintf("%s (0x%X)", t.string(), uint32(t))
}

func (t EventType) string() string {
	switch t {
	case EV_PREBOOT_CERT:
		return "EV_PREBOOT_CERT"
	case EV_POST_CODE:
		return "EV_POST_CODE"
	case EV_UNUSED:
		return "EV_UNUSED"
	case EV_NO_ACTION:
		return "EV_NO_ACTION"
	case EV_SEPARATOR:
		return "EV_SEPARATOR"
	case EV_ACTION:
		return "EV_ACTION"
	case EV_EVENT_TAG:
		return "EV_EVENT_TAG"
	case EV_S_CRTM_CONTENTS:
		return "EV_S_CRTM_CONTENTS"
	case EV_S_CRTM_VERSION:
		return "EV_S_CRTM_VERSION"
	case EV_CPU_MICROCODE:
		return "EV_CPU_MICROCODE"
	case EV_PLATFORM_CONFIG_FLAGS:
		return "EV_PLATFORM_CONFIG_FLAGS"
	case EV_TABLE_OF_DEVICES:
		return "EV_TABLE_OF_DEVICES"
	case EV_COMPACT_HASH:
		return "EV_COMPACT_HASH"
	case EV_IPL:
		return "EV_IPL"
	case EV_IPL_PARTITION_DATA:
		return "EV_IPL_PARTITION_DATA"
	case EV_NONHOST_CODE:
		return "EV_NONHOST_CODE"
	case EV_NONHOST_CONFIG:
		return "EV_NONHOST_CONFIG"
	case EV_NONHOST_INFO:
		return "EV_NONHOST_INFO"
	case EV_OMIT_BOOT_DEVICE_EVENTS:
		return "EV_OMIT_BOOT_DEVICE_EVENTS"
	case EV_EFI_EVENT_BASE:
		return "EV_EFI_EVENT_BASE"
	case EV_EFI_VARIABLE_DRIVER_CONFIG:
		return "EV_EFI_VARIABLE_DRIVER_CONFIG"
	case EV_EFI_VARIABLE_BOOT:
		return "EV_EFI_VARIABLE_BOOT"
	case EV_EFI_BOOT_SERVICES_APPLICATION:
		return "EV_EFI_BOOT_SERVICES_APPLICATION"
	case EV_EFI_BOOT_SERVICES_DRIVER:
		return "EV_EFI_BOOT_SERVICES_DRIVER"
	case EV_EFI_RUNTIME_SERVICES_DRIVER:
		return "EV_EFI_RUNTIME_SERVICES_DRIVER"
	case EV_EFI_GPT_EVENT:
		return "EV_EFI_GPT_EVENT"
	case EV_EFI_ACTION:
		return "EV_EFI_ACTION"
	case EV_EFI_PLATFORM_FIRMWARE_BLOB:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB"
	case EV_EFI_HANDOFF_TABLES:
		return "EV_EFI_HANDOFF_TABLES"
	case EV_EFI_PLATFORM_FIRMWARE_BLOB2:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB2"
	case EV_EFI_HCRTM_EVENT:
		return "EV_EFI_HCRTM_EVENT"
	case EV_EFI_VARIABLE_AUTHORITY:
		return "EV_EFI_VARIABLE_AUTHORITY"
	default:
		return fmt.Sprintf("unknown_%X", uint32(t))
	}
}
