package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSMESupport tests the SMESupport function
func TestSMESupport(t *testing.T) {
	tests := []struct {
		name          string
		cpuidEAX      uint32
		expectPass    bool
		expectTestErr bool
	}{
		{
			name:          "SME supported - bit 0 set",
			cpuidEAX:      CPUID_SME_SUPPORT, // 0x1
			expectPass:    true,
			expectTestErr: false,
		},
		{
			name:          "SME not supported - bit 0 unset",
			cpuidEAX:      0x0,
			expectPass:    false,
			expectTestErr: true,
		},
		{
			name:          "Multiple features set including SME",
			cpuidEAX:      CPUID_SME_SUPPORT | CPUID_SEV_SUPPORT | CPUID_SEV_ES_SUPPORT,
			expectPass:    true,
			expectTestErr: false,
		},
		{
			name:          "Only other features set, not SME",
			cpuidEAX:      CPUID_SEV_SUPPORT | CPUID_SEV_ES_SUPPORT,
			expectPass:    false,
			expectTestErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				CPUIDFunc: func(eax, ecx uint32) (uint32, uint32, uint32, uint32) {
					assert.Equal(t, CPUID_SME_SEV, eax, "Should query correct CPUID leaf")
					assert.Equal(t, uint32(0), ecx, "ECX should be 0")
					return tt.cpuidEAX, 0, 0, 0
				},
			}

			pass, testErr, internalErr := SMESupport(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass, "Return value should match expected")
			if tt.expectTestErr {
				assert.NotNil(t, testErr, "Should return test error")
				assert.Nil(t, internalErr, "Should not return internal error")
				assert.Contains(t, testErr.Error(), "SME is not supported")
			} else {
				assert.Nil(t, testErr, "Should not return test error")
				assert.Nil(t, internalErr, "Should not return internal error")
			}
		})
	}
}

// TestTSMESupport tests the TSMESupport function
func TestTSMESupport(t *testing.T) {
	tests := []struct {
		name          string
		cpuidEAX      uint32
		expectPass    bool
		expectTestErr bool
	}{
		{
			name:          "TSME supported - bit 13 set",
			cpuidEAX:      CPUID_TSME_SUPPORT, // 0x2000
			expectPass:    true,
			expectTestErr: false,
		},
		{
			name:          "TSME not supported - bit 13 unset",
			cpuidEAX:      0x0,
			expectPass:    false,
			expectTestErr: true,
		},
		{
			name:          "TSME with other features",
			cpuidEAX:      CPUID_TSME_SUPPORT | CPUID_SME_SUPPORT,
			expectPass:    true,
			expectTestErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				CPUIDFunc: func(eax, ecx uint32) (uint32, uint32, uint32, uint32) {
					assert.Equal(t, CPUID_SME_SEV, eax)
					return tt.cpuidEAX, 0, 0, 0
				},
			}

			pass, testErr, internalErr := TSMESupport(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Nil(t, internalErr)
				assert.Contains(t, testErr.Error(), "TSME is not supported")
			} else {
				assert.Nil(t, testErr)
				assert.Nil(t, internalErr)
			}
		})
	}
}

// TestSEVSupport tests the SEVSupport function
func TestSEVSupport(t *testing.T) {
	tests := []struct {
		name          string
		cpuidEAX      uint32
		expectPass    bool
		expectTestErr bool
	}{
		{
			name:          "SEV supported - bit 1 set",
			cpuidEAX:      CPUID_SEV_SUPPORT, // 0x2
			expectPass:    true,
			expectTestErr: false,
		},
		{
			name:          "SEV not supported - bit 1 unset",
			cpuidEAX:      0x0,
			expectPass:    false,
			expectTestErr: true,
		},
		{
			name:          "SEV with SME",
			cpuidEAX:      CPUID_SEV_SUPPORT | CPUID_SME_SUPPORT,
			expectPass:    true,
			expectTestErr: false,
		},
		{
			name:          "Only SME, not SEV",
			cpuidEAX:      CPUID_SME_SUPPORT,
			expectPass:    false,
			expectTestErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				CPUIDFunc: func(eax, ecx uint32) (uint32, uint32, uint32, uint32) {
					assert.Equal(t, CPUID_SME_SEV, eax)
					return tt.cpuidEAX, 0, 0, 0
				},
			}

			pass, testErr, internalErr := SEVSupport(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Nil(t, internalErr)
				assert.Contains(t, testErr.Error(), "SEV is not supported")
			} else {
				assert.Nil(t, testErr)
				assert.Nil(t, internalErr)
			}
		})
	}
}

// TestSEVESSupport tests the SEVESSupport function
func TestSEVESSupport(t *testing.T) {
	tests := []struct {
		name          string
		cpuidEAX      uint32
		expectPass    bool
		expectTestErr bool
	}{
		{
			name:          "SEV-ES supported - bit 3 set",
			cpuidEAX:      CPUID_SEV_ES_SUPPORT, // 0x8
			expectPass:    true,
			expectTestErr: false,
		},
		{
			name:          "SEV-ES not supported - bit 3 unset",
			cpuidEAX:      0x0,
			expectPass:    false,
			expectTestErr: true,
		},
		{
			name:          "SEV-ES with SEV and SME",
			cpuidEAX:      CPUID_SEV_ES_SUPPORT | CPUID_SEV_SUPPORT | CPUID_SME_SUPPORT,
			expectPass:    true,
			expectTestErr: false,
		},
		{
			name:          "Only SEV, not SEV-ES",
			cpuidEAX:      CPUID_SEV_SUPPORT,
			expectPass:    false,
			expectTestErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				CPUIDFunc: func(eax, ecx uint32) (uint32, uint32, uint32, uint32) {
					assert.Equal(t, CPUID_SME_SEV, eax)
					return tt.cpuidEAX, 0, 0, 0
				},
			}

			pass, testErr, internalErr := SEVESSupport(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Nil(t, internalErr)
				assert.Contains(t, testErr.Error(), "SEV-ES is not supported")
			} else {
				assert.Nil(t, testErr)
				assert.Nil(t, internalErr)
			}
		})
	}
}

// TestSEVSNPSupport tests the SEVSNPSupport function
func TestSEVSNPSupport(t *testing.T) {
	tests := []struct {
		name          string
		cpuidEAX      uint32
		expectPass    bool
		expectTestErr bool
	}{
		{
			name:          "SEV-SNP supported - bit 4 set",
			cpuidEAX:      CPUID_SEV_SNP_SUPPORT, // 0x10
			expectPass:    true,
			expectTestErr: false,
		},
		{
			name:          "SEV-SNP not supported - bit 4 unset",
			cpuidEAX:      0x0,
			expectPass:    false,
			expectTestErr: true,
		},
		{
			name:          "All SEV features enabled",
			cpuidEAX:      CPUID_SEV_SNP_SUPPORT | CPUID_SEV_ES_SUPPORT | CPUID_SEV_SUPPORT | CPUID_SME_SUPPORT,
			expectPass:    true,
			expectTestErr: false,
		},
		{
			name:          "SEV-ES but not SEV-SNP",
			cpuidEAX:      CPUID_SEV_ES_SUPPORT | CPUID_SEV_SUPPORT,
			expectPass:    false,
			expectTestErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				CPUIDFunc: func(eax, ecx uint32) (uint32, uint32, uint32, uint32) {
					assert.Equal(t, CPUID_SME_SEV, eax)
					return tt.cpuidEAX, 0, 0, 0
				},
			}

			pass, testErr, internalErr := SEVSNPSupport(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Nil(t, internalErr)
				assert.Contains(t, testErr.Error(), "SEV-SNP is not supported")
			} else {
				assert.Nil(t, testErr)
				assert.Nil(t, internalErr)
			}
		})
	}
}
