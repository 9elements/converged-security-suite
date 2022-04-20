package firmware

import _ "embed"

//go:embed fake_intel_firmware.fd
var FakeIntelFirmware []byte
