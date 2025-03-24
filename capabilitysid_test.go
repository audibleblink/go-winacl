package winacl_test

import (
	"testing"

	"github.com/audibleblink/go-winacl"
	"github.com/stretchr/testify/require"
)

func TestIsCapabilitySID(t *testing.T) {
	r := require.New(t)
	
	// Create a capability SID
	capabilitySID := winacl.SID{
		Revision:       1,
		NumAuthorities: 2,
		Authority:      []byte{0, 0, 0, 0, 0, 15}, // 15 is for app package authority
		SubAuthorities: []uint32{3, 1},            // 3 is capability, 1 is internetClient
	}
	
	r.True(winacl.IsCapabilitySID(capabilitySID))
	
	// Create a non-capability SID
	nonCapabilitySID := winacl.SID{
		Revision:       1,
		NumAuthorities: 1,
		Authority:      []byte{0, 0, 0, 0, 0, 5}, // 5 is NT Authority
		SubAuthorities: []uint32{18},             // 18 is Local System
	}
	
	r.False(winacl.IsCapabilitySID(nonCapabilitySID))
}

func TestCapabilityFromSID(t *testing.T) {
	r := require.New(t)
	
	// Create a known capability SID (internetClient)
	internetClientSID := winacl.SID{
		Revision:       1,
		NumAuthorities: 2,
		Authority:      []byte{0, 0, 0, 0, 0, 15}, // 15 is for app package authority
		SubAuthorities: []uint32{3, 1},            // 3 is capability, 1 is internetClient
	}
	
	capability, err := winacl.CapabilityFromSID(internetClientSID)
	r.NoError(err)
	r.Equal("internetClient", capability)
	
	// Create a custom capability SID
	customCapabilitySID := winacl.SID{
		Revision:       1,
		NumAuthorities: 3,
		Authority:      []byte{0, 0, 0, 0, 0, 15}, // 15 is for app package authority
		SubAuthorities: []uint32{3, 999, 888},     // 3 is capability, others are custom values
	}
	
	customCapability, err := winacl.CapabilityFromSID(customCapabilitySID)
	r.NoError(err)
	r.Contains(customCapability, "CustomCapability-")
	
	// Test with non-capability SID
	nonCapabilitySID := winacl.SID{
		Revision:       1,
		NumAuthorities: 1,
		Authority:      []byte{0, 0, 0, 0, 0, 5}, // 5 is NT Authority
		SubAuthorities: []uint32{18},             // 18 is Local System
	}
	
	_, err = winacl.CapabilityFromSID(nonCapabilitySID)
	r.Error(err)
	r.Contains(err.Error(), "not a capability SID")
}

func TestSIDFromCapability(t *testing.T) {
	r := require.New(t)
	
	// Test creating a SID from a well-known capability
	sid, err := winacl.SIDFromCapability("internetClient")
	r.NoError(err)
	r.Equal(byte(1), sid.Revision)
	r.Equal(byte(2), sid.NumAuthorities)
	r.Equal(byte(15), sid.Authority[5])
	r.Equal(uint32(3), sid.SubAuthorities[0])  // 3 is capability
	r.Equal(uint32(1), sid.SubAuthorities[1])  // 1 is internetClient
	
	// Verify the string representation
	r.Equal("S-1-15-3-1", sid.String())
	
	// Test creating a SID from a custom capability
	customSid, err := winacl.SIDFromCapability("CustomCapability-999-888")
	r.NoError(err)
	r.Equal(byte(1), customSid.Revision)
	r.Equal(byte(3), customSid.NumAuthorities)
	r.Equal(byte(15), customSid.Authority[5])
	r.Equal(uint32(3), customSid.SubAuthorities[0])   // 3 is capability
	r.Equal(uint32(999), customSid.SubAuthorities[1]) // Custom value
	r.Equal(uint32(888), customSid.SubAuthorities[2]) // Custom value
	
	// Test with unknown capability
	_, err = winacl.SIDFromCapability("nonExistentCapability")
	r.Error(err)
	r.Contains(err.Error(), "unknown capability")
}

func TestParseCapabilitySID(t *testing.T) {
	r := require.New(t)
	
	// Create binary data representing a capability SID
	// S-1-15-3-1 (internetClient)
	sidData := []byte{
		1,                      // Revision
		2,                      // NumAuthorities
		0, 0, 0, 0, 0, 15,      // Authority (15)
		3, 0, 0, 0,             // SubAuthority[0] = 3 (capability)
		1, 0, 0, 0,             // SubAuthority[1] = 1 (internetClient)
	}
	
	sid, err := winacl.ParseCapabilitySID(sidData)
	r.NoError(err)
	r.Equal(byte(1), sid.Revision)
	r.Equal(byte(2), sid.NumAuthorities)
	r.Equal(byte(15), sid.Authority[5])
	r.Equal(uint32(3), sid.SubAuthorities[0])
	r.Equal(uint32(1), sid.SubAuthorities[1])
	r.Equal("S-1-15-3-1", sid.String())
	
	// Test with invalid data
	invalidData := []byte{1, 2, 3} // Too short
	_, err = winacl.ParseCapabilitySID(invalidData)
	r.Error(err)
	r.Contains(err.Error(), "data too short")
	
	// Test with wrong revision
	wrongRevision := []byte{
		2,                      // Wrong revision
		2,                      // NumAuthorities
		0, 0, 0, 0, 0, 15,      // Authority
		3, 0, 0, 0,             // SubAuthority
		1, 0, 0, 0,             // SubAuthority
	}
	
	_, err = winacl.ParseCapabilitySID(wrongRevision)
	r.Error(err)
	r.Contains(err.Error(), "invalid revision")
}
