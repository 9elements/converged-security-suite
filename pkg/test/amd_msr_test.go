package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSMEEnabled tests the SMEEnabled function
func TestSMEEnabled(t *testing.T) {
	tests := []struct {
		name           string
		msrValues      []uint64
		expectPass     bool
		expectTestErr  bool
		expectIntErr   bool
	}{
		{
			name:          "SME enabled - bit 23 set",
			msrValues:     []uint64{MSR_AMD64_SYSCFG_SME_ENABLE},
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "SME not enabled - bit 23 unset",
			msrValues:     []uint64{0x0},
			expectPass:    false,
			expectTestErr: true,
			expectIntErr:  false,
		},
		{
			name:          "SME with other SYSCFG bits set",
			msrValues:     []uint64{MSR_AMD64_SYSCFG_SME_ENABLE | MSR_AMD64_SYSCFG_SEVSNP_ENABLE},
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "No MSR values returned - internal error",
			msrValues:     []uint64{},
			expectPass:    false,
			expectTestErr: false,
			expectIntErr:  true,
		},
		{
			name:          "Other bits set but not SME",
			msrValues:     []uint64{MSR_AMD64_SYSCFG_SEVSNP_ENABLE},
			expectPass:    false,
			expectTestErr: true,
			expectIntErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				ReadMSRFunc: func(msr int64) []uint64 {
					assert.Equal(t, int64(MSR_AMD64_SYSCFG), msr, "Should read correct MSR")
					return tt.msrValues
				},
			}

			pass, testErr, internalErr := SMEEnabled(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Nil(t, internalErr)
				assert.Contains(t, testErr.Error(), "SME is not enabled")
			} else if tt.expectIntErr {
				assert.Nil(t, testErr)
				assert.NotNil(t, internalErr)
				assert.Contains(t, internalErr.Error(), "reading MSRs returned no values")
			} else {
				assert.Nil(t, testErr)
				assert.Nil(t, internalErr)
			}
		})
	}
}

// TestTSMEEnabled tests the TSMEEnabled function
func TestTSMEEnabled(t *testing.T) {
	tests := []struct {
		name          string
		msrValues     []uint64
		expectPass    bool
		expectTestErr bool
		expectIntErr  bool
	}{
		{
			name:          "TSME enabled - bit 18 set",
			msrValues:     []uint64{MSR_AMD64_SYSCFG_TSME_EN},
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "TSME not enabled - bit 18 unset",
			msrValues:     []uint64{0x0},
			expectPass:    false,
			expectTestErr: true,
			expectIntErr:  false,
		},
		{
			name:          "TSME with SME enabled",
			msrValues:     []uint64{MSR_AMD64_SYSCFG_TSME_EN | MSR_AMD64_SYSCFG_SME_ENABLE},
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "Empty MSR array - internal error",
			msrValues:     []uint64{},
			expectPass:    false,
			expectTestErr: false,
			expectIntErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				ReadMSRFunc: func(msr int64) []uint64 {
					assert.Equal(t, int64(MSR_AMD64_SYSCFG), msr)
					return tt.msrValues
				},
			}

			pass, testErr, internalErr := TSMEEnabled(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Nil(t, internalErr)
				assert.Contains(t, testErr.Error(), "TSME is not enabled")
			} else if tt.expectIntErr {
				assert.Nil(t, testErr)
				assert.NotNil(t, internalErr)
				assert.Contains(t, internalErr.Error(), "ReadMSR returned no values")
			} else {
				assert.Nil(t, testErr)
				assert.Nil(t, internalErr)
			}
		})
	}
}

// TestSEVSNPEnabled tests the SEVSNPEnabled function
func TestSEVSNPEnabled(t *testing.T) {
	tests := []struct {
		name          string
		msrValues     []uint64
		expectPass    bool
		expectTestErr bool
		expectIntErr  bool
	}{
		{
			name:          "SEV-SNP enabled - bit 24 set",
			msrValues:     []uint64{MSR_AMD64_SYSCFG_SEVSNP_ENABLE},
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "SEV-SNP not enabled - bit 24 unset",
			msrValues:     []uint64{0x0},
			expectPass:    false,
			expectTestErr: true,
			expectIntErr:  false,
		},
		{
			name:          "SEV-SNP with SME enabled",
			msrValues:     []uint64{MSR_AMD64_SYSCFG_SEVSNP_ENABLE | MSR_AMD64_SYSCFG_SME_ENABLE},
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "Empty MSR array - internal error",
			msrValues:     []uint64{},
			expectPass:    false,
			expectTestErr: false,
			expectIntErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				ReadMSRFunc: func(msr int64) []uint64 {
					assert.Equal(t, int64(MSR_AMD64_SYSCFG), msr)
					return tt.msrValues
				},
			}

			pass, testErr, internalErr := SEVSNPEnabled(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Nil(t, internalErr)
			} else if tt.expectIntErr {
				assert.Nil(t, testErr)
				assert.NotNil(t, internalErr)
				assert.Contains(t, internalErr.Error(), "unable to red MSR")
			} else {
				assert.Nil(t, testErr)
				assert.Nil(t, internalErr)
			}
		})
	}
}

// TestSEVGuestSEVEnabledInMSR tests the SEVGuestSEVEnabledInMSR function
func TestSEVGuestSEVEnabledInMSR(t *testing.T) {
	tests := []struct {
		name          string
		msrValues     []uint64
		expectPass    bool
		expectTestErr bool
		expectIntErr  bool
	}{
		{
			name:          "SEV enabled in guest - bit 0 set",
			msrValues:     []uint64{MSR_AMD64_SEV_ENABLED},
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "SEV not enabled in guest - bit 0 unset",
			msrValues:     []uint64{0x0},
			expectPass:    false,
			expectTestErr: true,
			expectIntErr:  false,
		},
		{
			name:          "SEV with SEV-ES enabled",
			msrValues:     []uint64{MSR_AMD64_SEV_ENABLED | MSR_AMD64_SEV_ES_ENABLED},
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "Empty MSR array - internal error",
			msrValues:     []uint64{},
			expectPass:    false,
			expectTestErr: false,
			expectIntErr:  true,
		},
		{
			name:          "Only SEV-ES enabled, not SEV",
			msrValues:     []uint64{MSR_AMD64_SEV_ES_ENABLED},
			expectPass:    false,
			expectTestErr: true,
			expectIntErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				ReadMSRFunc: func(msr int64) []uint64 {
					assert.Equal(t, int64(MSR_AMD64_SEV), msr, "Should read SEV MSR")
					return tt.msrValues
				},
			}

			pass, testErr, internalErr := SEVGuestSEVEnabledInMSR(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Nil(t, internalErr)
				assert.Contains(t, testErr.Error(), "feature SEV is not enabled")
			} else if tt.expectIntErr {
				assert.Nil(t, testErr)
				assert.NotNil(t, internalErr)
				assert.Contains(t, internalErr.Error(), "unable to red MSR")
			} else {
				assert.Nil(t, testErr)
				assert.Nil(t, internalErr)
			}
		})
	}
}

// TestSEVGuestSEVESEnabled tests the SEVGuestSEVESEnabled function
func TestSEVGuestSEVESEnabled(t *testing.T) {
	tests := []struct {
		name          string
		msrValues     []uint64
		expectPass    bool
		expectTestErr bool
		expectIntErr  bool
	}{
		{
			name:          "SEV-ES enabled in guest - bit 1 set",
			msrValues:     []uint64{MSR_AMD64_SEV_ES_ENABLED},
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "SEV-ES not enabled in guest - bit 1 unset",
			msrValues:     []uint64{0x0},
			expectPass:    false,
			expectTestErr: true,
			expectIntErr:  false,
		},
		{
			name:          "Both SEV and SEV-ES enabled",
			msrValues:     []uint64{MSR_AMD64_SEV_ENABLED | MSR_AMD64_SEV_ES_ENABLED},
			expectPass:    true,
			expectTestErr: false,
			expectIntErr:  false,
		},
		{
			name:          "Empty MSR array - internal error",
			msrValues:     []uint64{},
			expectPass:    false,
			expectTestErr: false,
			expectIntErr:  true,
		},
		{
			name:          "Only SEV enabled, not SEV-ES",
			msrValues:     []uint64{MSR_AMD64_SEV_ENABLED},
			expectPass:    false,
			expectTestErr: true,
			expectIntErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockHardwareAPI{
				ReadMSRFunc: func(msr int64) []uint64 {
					assert.Equal(t, int64(MSR_AMD64_SEV), msr)
					return tt.msrValues
				},
			}

			pass, testErr, internalErr := SEVGuestSEVESEnabled(mock, &PreSet{})

			assert.Equal(t, tt.expectPass, pass)
			if tt.expectTestErr {
				assert.NotNil(t, testErr)
				assert.Nil(t, internalErr)
				assert.Contains(t, testErr.Error(), "feature not enabled: SEV-ES")
			} else if tt.expectIntErr {
				assert.Nil(t, testErr)
				assert.NotNil(t, internalErr)
				assert.Contains(t, internalErr.Error(), "ReadMSR returned no values")
			} else {
				assert.Nil(t, testErr)
				assert.Nil(t, internalErr)
			}
		})
	}
}
