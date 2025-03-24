package winacl

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// CapabilitySIDPrefix is the standard prefix for Windows Capability SIDs
const CapabilitySIDPrefix = "S-1-15-3-"

// WellKnownCapabilities maps capability names to their corresponding SID strings
var WellKnownCapabilities = map[string]string{
	"internetClient":                     "S-1-15-3-1",
	"internetClientServer":               "S-1-15-3-2",
	"privateNetworkClientServer":         "S-1-15-3-3",
	"picturesLibrary":                    "S-1-15-3-4",
	"videosLibrary":                      "S-1-15-3-5",
	"musicLibrary":                       "S-1-15-3-6",
	"documentsLibrary":                   "S-1-15-3-7",
	"enterpriseAuthentication":           "S-1-15-3-8",
	"sharedUserCertificates":             "S-1-15-3-9",
	"removableStorage":                   "S-1-15-3-10",
	"appointments":                       "S-1-15-3-11",
	"contacts":                           "S-1-15-3-12",
	"location":                           "S-1-15-3-1024",
	"microphone":                         "S-1-15-3-1025",
	"webcam":                             "S-1-15-3-1026",
	"systemManagement":                   "S-1-15-3-1027",
	"appCertificates":                    "S-1-15-3-1028",
	"offlineMapsManagement":              "S-1-15-3-1029",
	"enterpriseCloudSSO":                 "S-1-15-3-1030",
	"remoteSystem":                       "S-1-15-3-1031",
	"sharedUserCertificatesImport":       "S-1-15-3-1032",
	"remoteSystemDetailedSettings":       "S-1-15-3-1033",
	"phoneCallHistoryPublic":             "S-1-15-3-1034",
	"spatialPerception":                  "S-1-15-3-1035",
	"deviceUnlock":                       "S-1-15-3-1037",
	"lowLevelDevices":                    "S-1-15-3-1038",
	"backgroundMediaRecording":           "S-1-15-3-1039",
	"cameraProcessingExtension":          "S-1-15-3-1040",
	"userDataTasks":                      "S-1-15-3-1041",
	"userActivityInactiveThresholdTimer": "S-1-15-3-1042",
	"cellularDeviceIdentity":             "S-1-15-3-1043",
	"cellularDeviceControl":              "S-1-15-3-1044",
	"protectedApp":                       "S-1-15-3-1045",
	"userDataSystem":                     "S-1-15-3-1046",
	"graphicsCapture":                    "S-1-15-3-1047",
	"globalMediaControl":                 "S-1-15-3-1048",
	"appLicensing":                       "S-1-15-3-1049",
}

// Reverse map of capability SIDs to their names
var capabilitySIDToName map[string]string

func init() {
	// Initialize the reverse map
	capabilitySIDToName = make(map[string]string, len(WellKnownCapabilities))
	for name, sid := range WellKnownCapabilities {
		capabilitySIDToName[sid] = name
	}
}

// IsCapabilitySID checks if a SID is a Windows capability SID
func IsCapabilitySID(sid SID) bool {
	sidStr := sid.String()
	return strings.HasPrefix(sidStr, CapabilitySIDPrefix)
}

// CapabilityFromSID extracts the capability name from a capability SID
func CapabilityFromSID(sid SID) (string, error) {
	if !IsCapabilitySID(sid) {
		return "", fmt.Errorf("not a capability SID: %s", sid.String())
	}

	sidStr := sid.String()
	
	// Check if it's a well-known capability
	if name, ok := capabilitySIDToName[sidStr]; ok {
		return name, nil
	}
	
	// Return the raw capability ID for custom capabilities
	return fmt.Sprintf("CustomCapability-%s", sidStr[len(CapabilitySIDPrefix):]), nil
}

// SIDFromCapability creates a SID from a capability name
func SIDFromCapability(capabilityName string) (SID, error) {
	// Check if it's a well-known capability
	if sidStr, ok := WellKnownCapabilities[capabilityName]; ok {
		// Parse the capability SID
		parts := strings.Split(sidStr, "-")
		if len(parts) < 5 {
			return SID{}, fmt.Errorf("invalid capability SID format: %s", sidStr)
		}
		
		// Create the SID
		sid := SID{
			Revision:       1,
			NumAuthorities: byte(len(parts) - 3), // S-1-15-X-Y-Z has 3 authorities
			Authority:      []byte{0, 0, 0, 0, 0, 15}, // 15 is for app package authority
			SubAuthorities: make([]uint32, len(parts)-3),
		}
		
		// Parse the sub-authorities
		for i := 0; i < len(sid.SubAuthorities); i++ {
			var val uint64
			_, err := fmt.Sscanf(parts[i+3], "%d", &val)
			if err != nil {
				return SID{}, fmt.Errorf("invalid sub-authority in capability SID: %w", err)
			}
			sid.SubAuthorities[i] = uint32(val)
		}
		
		return sid, nil
	}
	
	// Handle custom capability format: CustomCapability-X-Y-Z
	if strings.HasPrefix(capabilityName, "CustomCapability-") {
		parts := strings.Split(capabilityName[17:], "-")
		if len(parts) == 0 {
			return SID{}, fmt.Errorf("invalid custom capability format: %s", capabilityName)
		}
		
		// Create the SID
		sid := SID{
			Revision:       1,
			NumAuthorities: byte(len(parts) + 1), // +1 for the "3" in S-1-15-3-...
			Authority:      []byte{0, 0, 0, 0, 0, 15}, // 15 is for app package authority
			SubAuthorities: make([]uint32, len(parts)+1),
		}
		
		// First sub-authority is always 3 for capability SIDs
		sid.SubAuthorities[0] = 3
		
		// Parse the remaining custom sub-authorities
		for i := 0; i < len(parts); i++ {
			var val uint64
			_, err := fmt.Sscanf(parts[i], "%d", &val)
			if err != nil {
				return SID{}, fmt.Errorf("invalid sub-authority in custom capability: %w", err)
			}
			sid.SubAuthorities[i+1] = uint32(val)
		}
		
		return sid, nil
	}
	
	return SID{}, fmt.Errorf("unknown capability: %s", capabilityName)
}

// ParseCapabilitySID parses a capability SID from binary data
func ParseCapabilitySID(data []byte) (SID, error) {
	if len(data) < 8 {
		return SID{}, fmt.Errorf("data too short for capability SID")
	}
	
	// Verify it's a capability SID
	revision := data[0]
	if revision != 1 {
		return SID{}, fmt.Errorf("invalid revision for capability SID: %d", revision)
	}
	
	numAuth := data[1]
	if numAuth < 2 {
		return SID{}, fmt.Errorf("invalid authority count for capability SID: %d", numAuth)
	}
	
	// Create a new SID
	sid := SID{
		Revision:       revision,
		NumAuthorities: numAuth,
		Authority:      make([]byte, 6),
		SubAuthorities: make([]uint32, numAuth),
	}
	
	// Copy authority (should be 15 for app containers)
	copy(sid.Authority, data[2:8])
	
	// Ensure minimum length for sub-authorities
	minLength := 8 + 4*int(numAuth)
	if len(data) < minLength {
		return SID{}, fmt.Errorf("data too short for capability SID with %d sub-authorities", numAuth)
	}
	
	// Extract sub-authorities
	for i := 0; i < int(numAuth); i++ {
		offset := 8 + (i * 4)
		sid.SubAuthorities[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
	}
	
	// Verify it's a capability SID
	if sid.Authority[5] != 15 || (numAuth > 0 && sid.SubAuthorities[0] != 3) {
		return SID{}, fmt.Errorf("not a capability SID")
	}
	
	return sid, nil
}
