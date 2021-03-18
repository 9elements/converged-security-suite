package tpmeventlog

// EventType defines the kind of data reported by an Event.
//
// See also: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=103
type EventType uint32

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
	EV_EFI_HCRTM_EVENT               = EventType(0x80000010)
	EV_EFI_VARIABLE_AUTHORITY        = EventType(0x800000E0)
)
