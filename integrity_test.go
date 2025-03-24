package winacl_test

import (
	"testing"

	"github.com/audibleblink/go-winacl"
	"github.com/stretchr/testify/require"
)

func TestIntegrityLevelFromSID(t *testing.T) {
	r := require.New(t)
	
	// Create a Medium integrity level SID
	mediumSID := winacl.SID{
		Revision:       1,
		NumAuthorities: 1,
		Authority:      []byte{0, 0, 0, 0, 0, 16}, // 16 is for Mandatory Label Authority
		SubAuthorities: []uint32{8192},            // 8192 is Medium integrity
	}
	
	level, err := winacl.IntegrityLevelFromSID(mediumSID)
	r.NoError(err)
	r.Equal(winacl.IntegrityLevelMedium, level)
	r.Equal("Medium", level.String())
	
	// Create a SID that isn't an integrity level
	nonIntegritySID := winacl.SID{
		Revision:       1,
		NumAuthorities: 1,
		Authority:      []byte{0, 0, 0, 0, 0, 5}, // 5 is NT Authority
		SubAuthorities: []uint32{18},             // 18 is Local System
	}
	
	_, err = winacl.IntegrityLevelFromSID(nonIntegritySID)
	r.Error(err)
	r.Contains(err.Error(), "not an integrity level SID")
}

func TestIntegrityLevelToSID(t *testing.T) {
	r := require.New(t)
	
	// Test converting an integrity level to a SID
	sid := winacl.IntegrityLevelMedium.ToSID()
	r.Equal(byte(1), sid.Revision)
	r.Equal(byte(1), sid.NumAuthorities)
	r.Equal(byte(16), sid.Authority[5])
	r.Equal(uint32(winacl.IntegrityLevelMedium), sid.SubAuthorities[0])
	
	// Verify the string representation
	r.Equal("S-1-16-8192", sid.String())
}

func TestIntegrityLevelComparison(t *testing.T) {
	r := require.New(t)
	
	// Test comparison between integrity levels
	r.True(winacl.IntegrityLevelHigh.IsHigherThan(winacl.IntegrityLevelMedium))
	r.True(winacl.IntegrityLevelMedium.IsHigherThan(winacl.IntegrityLevelLow))
	r.False(winacl.IntegrityLevelLow.IsHigherThan(winacl.IntegrityLevelMedium))
	r.False(winacl.IntegrityLevelMedium.IsHigherThan(winacl.IntegrityLevelMedium)) // Equal
}

func TestIntegrityLevelCheckAccess(t *testing.T) {
	r := require.New(t)
	
	t.Run("NoWriteUp policy blocks write access", func(t *testing.T) {
		// Medium user accessing High object with NoWriteUp policy
		subjectLevel := winacl.IntegrityLevelMedium
		objectLevel := winacl.IntegrityLevelHigh
		policy := winacl.PolicyNoWriteUp
		
		// Write access should be blocked
		r.False(subjectLevel.CheckAccess(objectLevel, policy, winacl.AccessMaskGenericWrite))
		
		// Read access should be allowed
		r.True(subjectLevel.CheckAccess(objectLevel, policy, winacl.AccessMaskGenericRead))
	})
	
	t.Run("NoReadUp policy blocks read access", func(t *testing.T) {
		// Medium user accessing High object with NoReadUp policy
		subjectLevel := winacl.IntegrityLevelMedium
		objectLevel := winacl.IntegrityLevelHigh
		policy := winacl.PolicyNoReadUp
		
		// Read access should be blocked
		r.False(subjectLevel.CheckAccess(objectLevel, policy, winacl.AccessMaskGenericRead))
		
		// Write access should be allowed
		r.True(subjectLevel.CheckAccess(objectLevel, policy, winacl.AccessMaskGenericWrite))
	})
	
	t.Run("NoExecuteUp policy blocks execute access", func(t *testing.T) {
		// Medium user accessing High object with NoExecuteUp policy
		subjectLevel := winacl.IntegrityLevelMedium
		objectLevel := winacl.IntegrityLevelHigh
		policy := winacl.PolicyNoExecuteUp
		
		// Execute access should be blocked
		r.False(subjectLevel.CheckAccess(objectLevel, policy, winacl.AccessMaskGenericExecute))
		
		// Read access should be allowed
		r.True(subjectLevel.CheckAccess(objectLevel, policy, winacl.AccessMaskGenericRead))
	})
	
	t.Run("Same or higher integrity always allows access", func(t *testing.T) {
		// High user accessing Medium object
		subjectLevel := winacl.IntegrityLevelHigh
		objectLevel := winacl.IntegrityLevelMedium
		policy := winacl.PolicyNoWriteUp | winacl.PolicyNoReadUp | winacl.PolicyNoExecuteUp
		
		// All access should be allowed
		r.True(subjectLevel.CheckAccess(objectLevel, policy, winacl.AccessMaskGenericAll))
		
		// Equal integrity should also allow access
		r.True(winacl.IntegrityLevelMedium.CheckAccess(winacl.IntegrityLevelMedium, policy, winacl.AccessMaskGenericAll))
	})
}