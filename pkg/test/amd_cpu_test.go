package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAMDFamilyModel tests the AMDFamilyModel function
func TestAMDFamilyModel(t *testing.T) {
	tests := []struct {
		name          string
		vendorString  string
		cpuSignature  uint32
		expectPass    bool
		expectTestErr bool
		expectIntErr  bool
	}{
		{
			name:          "Valid AMD CPU - Family 17h Model 30h",
			vendorString:  "AuthenticAMD",
			cpuSignature:  0x00870F10, // Family 17h, Model 30h
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "Valid AMD CPU - Family 19h Model 20h",
			vendorString:  "AuthenticAMD",
			cpuSignature:  0x00A20F10, // Family 19h, Model 20h
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "Not an AMD CPU - Intel",
			vendorString:  "GenuineIntel",
			cpuSignature:  0x000906E9,
			expectPass:    false,
			expectTestErr: true,
			expectIntErr:  false,
		},
		{
			name:          "AMD CPU with family 0 - unsupported",
			vendorString:  "AuthenticAMD",
			cpuSignature:  0x00000000, // Family 0, Model 0
			expectPass:    false,
			expectTestErr: false,
			expectIntErr:  true,
		},
		{
			name:          "AMD CPU with model 0 but valid family",
			vendorString:  "AuthenticAMD",
			cpuSignature:  0x00800000, // Family 17h, Model 0
			expectPass:    false,
			expectTestErr: false,
			expectIntErr:  true,
		},
		{
			name:          "Valid AMD CPU - Family 23h Model 1h (Zen)",
			vendorString:  "AuthenticAMD",
			cpuSignature:  0x00800F11, // Family 23h, Model 1h
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				VersionStringFunc: func() string {
					return tt.vendorString
				},
				CPUSignatureFunc: func() uint32 {
					return tt.cpuSignature
				},
			}

			pass, testErr, internalErr := AMDFamilyModel(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Nil(t, internalErr)
				assert.Contains(t, testErr.Error(), "not an AMD CPU")
			} else if tt.expectIntErr {
				assert.Nil(t, testErr)
				assert.NotNil(t, internalErr)
			} else {
				assert.Nil(t, testErr)
				assert.Nil(t, internalErr)
			}
		})
	}
}

// TestGetPSPMMIOBase tests the getPSPMMIOBase helper function
// This is a pure function with no dependencies - easiest to test!
func TestGetPSPMMIOBase(t *testing.T) {
	tests := []struct {
		name         string
		family       uint32
		model        uint32
		expectedBase int64
	}{
		{
			name:         "Family 17h Model 30h - uses PSPMMIOBase1",
			family:       0x17,
			model:        0x30,
			expectedBase: PSPMMIOBase1,
		},
		{
			name:         "Family 17h Model 70h - uses PSPMMIOBase1",
			family:       0x17,
			model:        0x70,
			expectedBase: PSPMMIOBase1,
		},
		{
			name:         "Family 19h Model 20h - uses PSPMMIOBase1",
			family:       0x19,
			model:        0x20,
			expectedBase: PSPMMIOBase1,
		},
		{
			name:         "Family 17h Model 01h - uses PSPMMIOBase2",
			family:       0x17,
			model:        0x01,
			expectedBase: PSPMMIOBase2,
		},
		{
			name:         "Family 19h Model 01h - uses PSPMMIOBase2",
			family:       0x19,
			model:        0x01,
			expectedBase: PSPMMIOBase2,
		},
		{
			name:         "Family 23h Model 01h - uses PSPMMIOBase2",
			family:       0x17,
			model:        0x08,
			expectedBase: PSPMMIOBase2,
		},
		{
			name:         "Unknown family/model combination - defaults to PSPMMIOBase2",
			family:       0x15,
			model:        0x10,
			expectedBase: PSPMMIOBase2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPSPMMIOBase(tt.family, tt.model)
			assert.Equal(t, tt.expectedBase, result, "Should return correct PSP MMIO base address")
		})
	}
}
