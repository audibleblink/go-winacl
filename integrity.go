package winacl

import (
	"fmt"
	"strings"
)

// IntegrityLevel represents Windows integrity levels
// See: https://docs.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
type IntegrityLevel uint32

// Windows integrity level constants
const (
	IntegrityLevelUntrusted       IntegrityLevel = 0x0000
	IntegrityLevelLow             IntegrityLevel = 0x1000
	IntegrityLevelMedium          IntegrityLevel = 0x2000
	IntegrityLevelMediumPlus      IntegrityLevel = 0x2100
	IntegrityLevelHigh            IntegrityLevel = 0x3000
	IntegrityLevelSystem          IntegrityLevel = 0x4000
	IntegrityLevelProtected       IntegrityLevel = 0x5000
	IntegrityLevelSecureProcess   IntegrityLevel = 0x6000
)

// IntegrityLevelMap maps integrity level SIDs to their IntegrityLevel values
var IntegrityLevelMap = map[string]IntegrityLevel{
	"S-1-16-0":      IntegrityLevelUntrusted,
	"S-1-16-4096":   IntegrityLevelLow,
	"S-1-16-8192":   IntegrityLevelMedium,
	"S-1-16-8448":   IntegrityLevelMediumPlus,
	"S-1-16-12288":  IntegrityLevelHigh,
	"S-1-16-16384":  IntegrityLevelSystem,
	"S-1-16-20480":  IntegrityLevelProtected,
	"S-1-16-28672":  IntegrityLevelSecureProcess,
}

// IntegrityLevelNameMap maps IntegrityLevel values to human-readable names
var IntegrityLevelNameMap = map[IntegrityLevel]string{
	IntegrityLevelUntrusted:      "Untrusted",
	IntegrityLevelLow:            "Low",
	IntegrityLevelMedium:         "Medium",
	IntegrityLevelMediumPlus:     "Medium Plus",
	IntegrityLevelHigh:           "High",
	IntegrityLevelSystem:         "System",
	IntegrityLevelProtected:      "Protected Process",
	IntegrityLevelSecureProcess:  "Secure Process",
}

// IntegrityLevelFromSID extracts the integrity level from a SID string
// Windows integrity level SIDs have the format S-1-16-X
func IntegrityLevelFromSID(sid SID) (IntegrityLevel, error) {
	sidStr := sid.String()
	
	// Check if this is an integrity level SID
	if !strings.HasPrefix(sidStr, "S-1-16-") {
		return 0, fmt.Errorf("not an integrity level SID: %s", sidStr)
	}
	
	if level, ok := IntegrityLevelMap[sidStr]; ok {
		return level, nil
	}
	
	// Try to extract the raw level value if it's not in our map
	var rawLevel uint32
	if len(sid.SubAuthorities) > 0 {
		rawLevel = sid.SubAuthorities[0]
	}
	
	return IntegrityLevel(rawLevel), nil
}

// String returns the human-readable name of the integrity level
func (il IntegrityLevel) String() string {
	if name, ok := IntegrityLevelNameMap[il]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", il)
}

// ToSID converts the integrity level to a SID
func (il IntegrityLevel) ToSID() SID {
	// Integrity level SIDs always have the format S-1-16-XXXX
	// where XXXX is the integrity level value
	return SID{
		Revision:       1,
		NumAuthorities: 1,
		Authority:      []byte{0, 0, 0, 0, 0, 16}, // 16 is Mandatory Label Authority
		SubAuthorities: []uint32{uint32(il)},
	}
}

// IsHigherThan checks if this integrity level is higher than the provided level
func (il IntegrityLevel) IsHigherThan(other IntegrityLevel) bool {
	return il > other
}

// IntegrityLevelPolicy defines how the integrity level check affects access
type IntegrityLevelPolicy uint32

// IntegrityLevelPolicy constants
const (
	PolicyNoWriteUp   IntegrityLevelPolicy = 0x1 // Prevents write access to higher integrity objects
	PolicyNoReadUp    IntegrityLevelPolicy = 0x2 // Prevents read access to higher integrity objects
	PolicyNoExecuteUp IntegrityLevelPolicy = 0x4 // Prevents execute access to higher integrity objects
)

// CheckAccess evaluates if a subject with this integrity level can access
// an object with the specified integrity level given the policy
func (il IntegrityLevel) CheckAccess(objectLevel IntegrityLevel, policy IntegrityLevelPolicy, requestedAccess uint32) bool {
	// If subject level is higher or equal to object level, always grant access
	if il >= objectLevel {
		return true
	}

	// Subject level is lower than object level, apply policy
	if (policy&PolicyNoWriteUp != 0) && 
	   (requestedAccess&(AccessMaskGenericWrite|AccessMaskWriteDACL|AccessMaskWriteOwner) != 0) {
		return false
	}
	
	if (policy&PolicyNoReadUp != 0) && 
	   (requestedAccess&(AccessMaskGenericRead|AccessMaskReadControl) != 0) {
		return false
	}
	
	if (policy&PolicyNoExecuteUp != 0) && 
	   (requestedAccess&AccessMaskGenericExecute != 0) {
		return false
	}

	return true
}
