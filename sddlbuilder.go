package winacl

import (
	"fmt"
	"strings"
)

// SDDLBuilder provides a fluent API for constructing Security Descriptor Definition Language strings
type SDDLBuilder struct {
	owner     string // SID or special name
	group     string // SID or special name
	dacl      []string // ACE strings
	sacl      []string // ACE strings
	flags     uint16 // Security descriptor control flags
	useOwner  bool
	useGroup  bool
	useDacl   bool
	useSacl   bool
	useFlags  bool
}

// NewSDDLBuilder creates a new SDDL builder instance
func NewSDDLBuilder() *SDDLBuilder {
	return &SDDLBuilder{
		dacl: make([]string, 0),
		sacl: make([]string, 0),
	}
}

// WithOwner sets the owner SID in the security descriptor
func (sb *SDDLBuilder) WithOwner(sid string) *SDDLBuilder {
	sb.owner = sid
	sb.useOwner = true
	return sb
}

// WithOwnerSID sets the owner SID in the security descriptor using a SID object
func (sb *SDDLBuilder) WithOwnerSID(sid SID) *SDDLBuilder {
	return sb.WithOwner(sid.String())
}

// WithGroup sets the group SID in the security descriptor
func (sb *SDDLBuilder) WithGroup(sid string) *SDDLBuilder {
	sb.group = sid
	sb.useGroup = true
	return sb
}

// WithGroupSID sets the group SID in the security descriptor using a SID object
func (sb *SDDLBuilder) WithGroupSID(sid SID) *SDDLBuilder {
	return sb.WithGroup(sid.String())
}

// WithFlags sets the security descriptor control flags
func (sb *SDDLBuilder) WithFlags(flags uint16) *SDDLBuilder {
	sb.flags = flags
	sb.useFlags = true
	return sb
}

// formatACL formats an ACL string from a slice of ACE strings
func (sb *SDDLBuilder) formatACL(aces []string) string {
	return strings.Join(aces, "")
}

// WithFlag adds a specific flag to the security descriptor
// Valid flags are: P (Protected), AI (Auto-Inherited), AR (Auto Inherit Required), etc.
func (sb *SDDLBuilder) WithFlag(flag string) *SDDLBuilder {
	// Define known flags
	flagMap := map[string]uint16{
		"P":   DACLProtected,
		"AR":  DACLAutoInheritReq,
		"AI":  DACLAutoInherited,
		"SA":  SACLAutoInherited,
		"SR":  0x0200, // SACL Auto Inherit Req
		"SP":  0x2000, // SACL Protected
		"NO":  0x0100, // No Owner propagate
		"NG":  0x0200, // No Group propagate
		"SD":  0x0001, // Self-relative
		"DT":  0x0008, // DACL Trusted
		"SS":  0x0008, // SACL Trusted
		"RM":  0x2000, // RM Control Valid
		"CR":  0x0010, // Create Revision
		"CO":  0x0004, // Control Access
		"SR1": 0x0800, // Server Security
	}

	if val, ok := flagMap[flag]; ok {
		sb.flags |= val
		sb.useFlags = true
	}
	
	return sb
}

// WithDACL adds a DACL to the security descriptor
func (sb *SDDLBuilder) WithDACL() *SDDLBuilder {
	sb.useDacl = true
	return sb
}

// WithSACL adds a SACL to the security descriptor
func (sb *SDDLBuilder) WithSACL() *SDDLBuilder {
	sb.useSacl = true
	return sb
}

// AccessAllowedACE adds an Access Allowed ACE to the DACL
func (sb *SDDLBuilder) AccessAllowedACE(sid string, accessMask uint32, flags byte) *SDDLBuilder {
	sb.useDacl = true
	aceString := fmt.Sprintf("(A;%s;%s;;;%s)", formatACEFlags(flags), formatAccessMask(accessMask), sid)
	sb.dacl = append(sb.dacl, aceString)
	return sb
}

// AccessDeniedACE adds an Access Denied ACE to the DACL
func (sb *SDDLBuilder) AccessDeniedACE(sid string, accessMask uint32, flags byte) *SDDLBuilder {
	sb.useDacl = true
	aceString := fmt.Sprintf("(D;%s;%s;;;%s)", formatACEFlags(flags), formatAccessMask(accessMask), sid)
	sb.dacl = append(sb.dacl, aceString)
	return sb
}

// AuditACE adds an Audit ACE to the SACL
func (sb *SDDLBuilder) AuditACE(sid string, accessMask uint32, flags byte, success, failure bool) *SDDLBuilder {
	sb.useSacl = true
	
	auditType := ""
	if success && failure {
		auditType = "AU"
	} else if success {
		auditType = "SA"
	} else if failure {
		auditType = "FA"
	}
	
	aceString := fmt.Sprintf("(%s;%s;%s;;;%s)", auditType, formatACEFlags(flags), formatAccessMask(accessMask), sid)
	sb.sacl = append(sb.sacl, aceString)
	return sb
}

// formatACEFlags converts ACE header flags to SDDL format
func formatACEFlags(flags byte) string {
	result := ""
	
	// Map flags to SDDL characters
	flagMap := map[byte]string{
		byte(ACEHeaderFlagsObjectInheritAce):        "OI",
		byte(ACEHeaderFlagsContainerInheritAce):     "CI",
		byte(ACEHeaderFlagsNoPropogateInheritAce):   "NP",
		byte(ACEHeaderFlagsInheritOnlyAce):          "IO",
		byte(ACEHeaderFlagsInheritedAce):            "ID",
		byte(ACEHeaderFlagsSuccessfulAccessAceFlag): "SA",
		byte(ACEHeaderFlagsFailedAccessAceFlag):     "FA",
	}
	
	for mask, flag := range flagMap {
		if flags&mask != 0 {
			result += flag
		}
	}
	
	return result
}

// formatAccessMask converts an access mask to SDDL format
func formatAccessMask(mask uint32) string {
	// Try using basic rights first
	basic := formatBasicAccessMask(mask)
	if basic != "" {
		return basic
	}
	
	// Otherwise, use hex format
	return fmt.Sprintf("0x%08X", mask)
}

// formatBasicAccessMask tries to format using well-known rights
func formatBasicAccessMask(mask uint32) string {
	// Map of standard access rights
	rightsMap := map[uint32]string{
		AccessMaskGenericAll:     "GA",
		AccessMaskGenericExecute: "GX",
		AccessMaskGenericWrite:   "GW",
		AccessMaskGenericRead:    "GR",
		AccessMaskMaximumAllowed: "MA",
		AccessMaskReadControl:    "RC",
		AccessMaskWriteDACL:      "WD",
		AccessMaskWriteOwner:     "WO",
		AccessMaskDelete:         "SD",
		AccessMaskSynchronize:    "SY",
	}
	
	// Check if exact well-known mask
	for right, code := range rightsMap {
		if mask == right {
			return code
		}
	}
	
	// Look for combination of rights
	result := ""
	for right, code := range rightsMap {
		if mask&right != 0 {
			result += code
		}
	}
	
	return result
}

// Build constructs the SDDL string
func (sb *SDDLBuilder) Build() string {
	var parts []string
	
	// Add owner if present
	if sb.useOwner {
		parts = append(parts, fmt.Sprintf("O:%s", sb.owner))
	}
	
	// Add group if present
	if sb.useGroup {
		parts = append(parts, fmt.Sprintf("G:%s", sb.group))
	}
	
	// Add DACL with flags if present
	if sb.useDacl {
		// Start with "D:"
		daclPart := "D:"
		
		// Add flags if present
		if sb.useFlags {
			daclPart += formatSDFlags(sb.flags)
		}
		
		// Add ACEs
		if len(sb.dacl) > 0 {
			daclPart += sb.formatACL(sb.dacl)
		}
		
		parts = append(parts, daclPart)
	} else if sb.useFlags {
		// If we have flags but no DACL, add them to their own part
		parts = append(parts, fmt.Sprintf("D:%s", formatSDFlags(sb.flags)))
	}
	
	// Add SACL if present
	if sb.useSacl {
		if len(sb.sacl) > 0 {
			parts = append(parts, fmt.Sprintf("S:%s", sb.formatACL(sb.sacl)))
		} else {
			parts = append(parts, "S:") // Empty SACL
		}
	}
	
	return strings.Join(parts, "")
}

// formatSDFlags formats security descriptor flags for SDDL
func formatSDFlags(flags uint16) string {
	result := ""
	
	// Map of flags to SDDL codes
	flagMap := map[uint16]string{
		DACLProtected:     "P",
		DACLAutoInheritReq: "AR",
		DACLAutoInherited: "AI",
		SACLAutoInherited: "SA",
		0x0200:            "SR", // SACL Auto Inherit Req
		0x2000:            "SP", // SACL Protected
	}
	
	for flag, code := range flagMap {
		if flags&flag != 0 {
			result += code
		}
	}
	
	return result
}

// Parse parses an SDDL string into a security descriptor
func (sb *SDDLBuilder) Parse(sddl string) (*NtSecurityDescriptor, error) {
	// This is a placeholder - implementing a full SDDL parser would be quite involved
	// and would duplicate functionality that might already exist elsewhere in the library
	// We'd need to integrate with existing parsing logic in the library
	
	// Placeholder error for now
	return nil, fmt.Errorf("SDDL parsing not implemented in the builder yet")
}
