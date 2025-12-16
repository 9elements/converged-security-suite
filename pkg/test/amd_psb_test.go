package test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper function to create a mock that returns specific PSB status value
func createPSBMock(family, model uint32, psbStatusValue uint64) *MockHardwareAPI {
	return &MockHardwareAPI{
		CPUSignatureFunc: func() uint32 {
			// AMD CPU signature format matches how AMDFamilyModel decodes it:
			// Family = ExtFamily[27:20] + BaseFamily[11:8]
			// Model = ExtModel[19:16] + BaseModel[7:4]
			// We need to encode the target family/model back into this format
			var baseFam, extFam, baseMod, extMod uint32

			if family > 0xF {
				baseFam = 0xF
				extFam = family - 0xF
			} else {
				baseFam = family
				extFam = 0
			}

			if model > 0xF {
				baseMod = model & 0xF
				extMod = (model >> 4) & 0xF
			} else {
				baseMod = model
				extMod = 0
			}

			return (extFam << 20) | (extMod << 16) | (baseFam << 8) | (baseMod << 4)
		},
		ReadPhysBufFunc: func(addr int64, buf []byte) error {
			if len(buf) < 8 {
				return fmt.Errorf("buffer too small")
			}
			// Write the PSB status value as little-endian uint64
			binary.LittleEndian.PutUint64(buf, psbStatusValue)
			return nil
		},
	}
}

// TestReadPSBStatus tests the readPSBStatus helper function
func TestReadPSBStatus(t *testing.T) {
	tests := []struct {
		name           string
		family         uint32
		model          uint32
		psbStatusValue uint64
		readPhysBufErr error
		expectError    bool
		expectedValue  uint64
	}{
		{
			name:           "Successful read - Family 17h Model 30h",
			family:         0x17,
			model:          0x30,
			psbStatusValue: 0x1234567890ABCDEF,
			readPhysBufErr: nil,
			expectError:    false,
			expectedValue:  0x1234567890ABCDEF,
		},
		{
			name:           "Successful read - Family 19h Model 20h",
			family:         0x19,
			model:          0x20,
			psbStatusValue: 0xFFFFFFFFFFFFFFFF,
			readPhysBufErr: nil,
			expectError:    false,
			expectedValue:  0xFFFFFFFFFFFFFFFF,
		},
		{
			name:           "Successful read - Zero value",
			family:         0x17,
			model:          0x01,
			psbStatusValue: 0x0,
			readPhysBufErr: nil,
			expectError:    false,
			expectedValue:  0x0,
		},
		{
			name:           "Read error - physical memory access fails",
			family:         0x17,
			model:          0x30,
			psbStatusValue: 0x0,
			readPhysBufErr: fmt.Errorf("cannot access physical memory"),
			expectError:    true,
			expectedValue:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				CPUSignatureFunc: func() uint32 {
					// AMD CPU signature encoding
					var baseFam, extFam, baseMod, extMod uint32

					if tt.family > 0xF {
						baseFam = 0xF
						extFam = tt.family - 0xF
					} else {
						baseFam = tt.family
						extFam = 0
					}

					if tt.model > 0xF {
						baseMod = tt.model & 0xF
						extMod = (tt.model >> 4) & 0xF
					} else {
						baseMod = tt.model
						extMod = 0
					}

					return (extFam << 20) | (extMod << 16) | (baseFam << 8) | (baseMod << 4)
				},
				ReadPhysBufFunc: func(addr int64, buf []byte) error {
					if tt.readPhysBufErr != nil {
						return tt.readPhysBufErr
					}
					// Verify correct address is being accessed
					expectedBase := getPSPMMIOBase(tt.family, tt.model)
					assert.Equal(t, expectedBase+PSBStatusOffset, addr)
					binary.LittleEndian.PutUint64(buf, tt.psbStatusValue)
					return nil
				},
			}

			value, err := readPSBStatus(mock)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedValue, value)
			}
		})
	}
}

// TestPSBStatus tests the PSBStatus function
func TestPSBStatus(t *testing.T) {
	tests := []struct {
		name           string
		psbStatusValue uint64
		expectPass     bool
		expectTestErr  bool
	}{
		{
			name:           "PSB Status is zero - pass",
			psbStatusValue: 0x0,
			expectPass:     true,
			expectTestErr:  false,
		},
		{
			name:           "PSB Status has error bits set - fail",
			psbStatusValue: 0xFF, // All error bits set
			expectPass:     false,
			expectTestErr:  true,
		},
		{
			name:           "PSB Status has one error bit set",
			psbStatusValue: 0x01,
			expectPass:     false,
			expectTestErr:  true,
		},
		{
			name:           "PSB Status has other bits set but not error bits",
			psbStatusValue: PSBFusedBit | DisableAMDKeyBit,
			expectPass:     true,
			expectTestErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := createPSBMock(0x17, 0x30, tt.psbStatusValue)

			pass, testErr, internalErr := PSBStatus(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			assert.Nil(t, internalErr)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Contains(t, testErr.Error(), "PSB_STATUS contains non-zero value")
			} else {
				assert.Nil(t, testErr)
			}
		})
	}
}

// TestPSBEnabled tests the PSBEnabled function
func TestPSBEnabled(t *testing.T) {
	tests := []struct {
		name           string
		psbStatusValue uint64
		expectPass     bool
		expectTestErr  bool
	}{
		{
			name:           "PSB enabled - bit 24 set",
			psbStatusValue: PSBFusedBit,
			expectPass:     true,
			expectTestErr:  false,
		},
		{
			name:           "PSB not enabled - bit 24 unset",
			psbStatusValue: 0x0,
			expectPass:     false,
			expectTestErr:  true,
		},
		{
			name:           "PSB enabled with other bits set",
			psbStatusValue: PSBFusedBit | DisableAMDKeyBit | DisableSecureDebugBit,
			expectPass:     true,
			expectTestErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := createPSBMock(0x17, 0x30, tt.psbStatusValue)

			pass, testErr, internalErr := PSBEnabled(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			assert.Nil(t, internalErr)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Contains(t, testErr.Error(), "Platform Secure Boot is not enabled")
			} else {
				assert.Nil(t, testErr)
			}
		})
	}
}

// TestPlatformVendorID tests the PlatformVendorID function
func TestPlatformVendorID(t *testing.T) {
	tests := []struct {
		name           string
		psbStatusValue uint64
		expectPass     bool
		expectTestErr  bool
	}{
		{
			name:           "Valid vendor ID - 0x42",
			psbStatusValue: 0x42,
			expectPass:     true,
			expectTestErr:  false,
		},
		{
			name:           "Invalid vendor ID - 0x0",
			psbStatusValue: 0x0,
			expectPass:     false,
			expectTestErr:  true,
		},
		{
			name:           "Vendor ID with other bits set",
			psbStatusValue: 0xFF | PSBFusedBit,
			expectPass:     true,
			expectTestErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := createPSBMock(0x17, 0x30, tt.psbStatusValue)

			pass, testErr, internalErr := PlatformVendorID(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			assert.Nil(t, internalErr)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Contains(t, testErr.Error(), "invalid Platform Vendor ID")
			} else {
				assert.Nil(t, testErr)
			}
		})
	}
}

// TestPlatformModelID tests the PlatformModelID function
func TestPlatformModelID(t *testing.T) {
	tests := []struct {
		name           string
		psbStatusValue uint64
		expectPass     bool
		expectTestErr  bool
	}{
		{
			name:           "Valid model ID - 0x1 in bits 8-11",
			psbStatusValue: 0x100, // bit 8 set
			expectPass:     true,
			expectTestErr:  false,
		},
		{
			name:           "Invalid model ID - 0x0",
			psbStatusValue: 0x0,
			expectPass:     false,
			expectTestErr:  true,
		},
		{
			name:           "Model ID 0xF with other bits",
			psbStatusValue: 0xF00 | PSBFusedBit,
			expectPass:     true,
			expectTestErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := createPSBMock(0x17, 0x30, tt.psbStatusValue)

			pass, testErr, internalErr := PlatformModelID(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			assert.Nil(t, internalErr)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Contains(t, testErr.Error(), "invalid Platform Model ID")
			} else {
				assert.Nil(t, testErr)
			}
		})
	}
}

// TestBIOSKeyRevision tests the BIOSKeyRevision function
func TestBIOSKeyRevision(t *testing.T) {
	tests := []struct {
		name           string
		psbStatusValue uint64
		expectPass     bool
		expectTestErr  bool
	}{
		{
			name:           "Valid BIOS key revision - 0x1 in bits 12-15",
			psbStatusValue: 0x1000, // bit 12 set
			expectPass:     true,
			expectTestErr:  false,
		},
		{
			name:           "Invalid BIOS key revision - 0x0",
			psbStatusValue: 0x0,
			expectPass:     false,
			expectTestErr:  true,
		},
		{
			name:           "BIOS key revision 0xF with other bits",
			psbStatusValue: 0xF000 | PSBFusedBit,
			expectPass:     true,
			expectTestErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := createPSBMock(0x17, 0x30, tt.psbStatusValue)

			pass, testErr, internalErr := BIOSKeyRevision(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			assert.Nil(t, internalErr)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Contains(t, testErr.Error(), "invalid BIOS Key Revision")
			} else {
				assert.Nil(t, testErr)
			}
		})
	}
}

// TestAMDKeyDisabled tests the AMDKeyDisabled function
func TestAMDKeyDisabled(t *testing.T) {
	tests := []struct {
		name           string
		psbStatusValue uint64
		expectPass     bool
		expectTestErr  bool
	}{
		{
			name:           "AMD key disabled - bit 26 set",
			psbStatusValue: DisableAMDKeyBit,
			expectPass:     true,
			expectTestErr:  false,
		},
		{
			name:           "AMD key not disabled - bit 26 unset",
			psbStatusValue: 0x0,
			expectPass:     false,
			expectTestErr:  true,
		},
		{
			name:           "AMD key disabled with other bits",
			psbStatusValue: DisableAMDKeyBit | PSBFusedBit,
			expectPass:     true,
			expectTestErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := createPSBMock(0x17, 0x30, tt.psbStatusValue)

			pass, testErr, internalErr := AMDKeyDisabled(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			assert.Nil(t, internalErr)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Contains(t, testErr.Error(), "AMD Key is not disabled")
			} else {
				assert.Nil(t, testErr)
			}
		})
	}
}

// TestSecureDebugDisabled tests the SecureDebugDisabled function
func TestSecureDebugDisabled(t *testing.T) {
	tests := []struct {
		name           string
		psbStatusValue uint64
		expectPass     bool
		expectTestErr  bool
	}{
		{
			name:           "Secure debug disabled - bit 27 set",
			psbStatusValue: DisableSecureDebugBit,
			expectPass:     true,
			expectTestErr:  false,
		},
		{
			name:           "Secure debug not disabled - bit 27 unset",
			psbStatusValue: 0x0,
			expectPass:     false,
			expectTestErr:  true,
		},
		{
			name:           "Secure debug disabled with other bits",
			psbStatusValue: DisableSecureDebugBit | PSBFusedBit | DisableAMDKeyBit,
			expectPass:     true,
			expectTestErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := createPSBMock(0x17, 0x30, tt.psbStatusValue)

			pass, testErr, internalErr := SecureDebugDisabled(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			assert.Nil(t, internalErr)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Contains(t, testErr.Error(), "invalid Secure Debug value")
			} else {
				assert.Nil(t, testErr)
			}
		})
	}
}

// TestKeysFused tests the KeysFused function
func TestKeysFused(t *testing.T) {
	tests := []struct {
		name           string
		psbStatusValue uint64
		expectPass     bool
		expectTestErr  bool
	}{
		{
			name:           "Keys fused - bit 28 set",
			psbStatusValue: CustomerKeyLockBit,
			expectPass:     true,
			expectTestErr:  false,
		},
		{
			name:           "Keys not fused - bit 28 unset",
			psbStatusValue: 0x0,
			expectPass:     false,
			expectTestErr:  true,
		},
		{
			name:           "Keys fused with other bits",
			psbStatusValue: CustomerKeyLockBit | PSBFusedBit | DisableAMDKeyBit,
			expectPass:     true,
			expectTestErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := createPSBMock(0x17, 0x30, tt.psbStatusValue)

			pass, testErr, internalErr := KeysFused(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			assert.Nil(t, internalErr)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Contains(t, testErr.Error(), "invalid value for Customer Key Lock bit")
			} else {
				assert.Nil(t, testErr)
			}
		})
	}
}

// TestRevocationStatus tests the RevocationStatus function
func TestRevocationStatus(t *testing.T) {
	tests := []struct {
		name           string
		psbStatusValue uint64
		expectPass     bool
		expectTestErr  bool
	}{
		{
			name:           "Anti-rollback enabled - bit 25 set",
			psbStatusValue: AntiRollbackBit,
			expectPass:     true,
			expectTestErr:  false,
		},
		{
			name:           "Anti-rollback not enabled - bit 25 unset",
			psbStatusValue: 0x0,
			expectPass:     false,
			expectTestErr:  true,
		},
		{
			name:           "Anti-rollback with other security bits",
			psbStatusValue: AntiRollbackBit | PSBFusedBit | DisableAMDKeyBit,
			expectPass:     true,
			expectTestErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := createPSBMock(0x17, 0x30, tt.psbStatusValue)

			pass, testErr, internalErr := RevocationStatus(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			assert.Nil(t, internalErr)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Contains(t, testErr.Error(), "feature Anti-rollback is not enabled")
			} else {
				assert.Nil(t, testErr)
			}
		})
	}
}
