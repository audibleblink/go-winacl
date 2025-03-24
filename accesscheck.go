package winacl

import (
	"fmt"
)

// AccessCheckResult represents the result of an access check operation
type AccessCheckResult struct {
	Granted bool           // Whether access was granted
	Reason  string         // Reason for the decision
	Ace     *ACE           // The ACE that determined the result, if any
	Access  uint32         // Access mask that was granted
	Details []CheckDetails // Detailed reasoning about the check
}

// CheckDetails provides detailed information about a step in the access check
type CheckDetails struct {
	Step        string
	Description string
	Outcome     bool
}

// TokenUser represents a user in a security token
type TokenUser struct {
	UserSID SID
	Groups  []SID
	Flags   uint32 // Flags that control how groups are used
}

// NewTokenUser creates a new TokenUser object
func NewTokenUser(userSID SID, groups []SID) *TokenUser {
	return &TokenUser{
		UserSID: userSID,
		Groups:  groups,
		Flags:   0,
	}
}

// AccessCheckOptions provides configuration for access checks
type AccessCheckOptions struct {
	IgnoreObjectType  bool // Skip object type checks for object ACEs
	CheckIntegrity    bool // Check integrity levels
	IntegrityPolicy   IntegrityLevelPolicy
	SubjectIntegrity  IntegrityLevel // Subject's integrity level
	ObjectIntegrity   IntegrityLevel // Object's integrity level
	GenericMapping    map[uint32]uint32
}

// DefaultAccessCheckOptions returns a default set of access check options
func DefaultAccessCheckOptions() *AccessCheckOptions {
	return &AccessCheckOptions{
		IgnoreObjectType: true,
		CheckIntegrity:   false,
		IntegrityPolicy:  PolicyNoWriteUp,
		GenericMapping: map[uint32]uint32{
			AccessMaskGenericRead:    AccessMaskReadControl,
			AccessMaskGenericWrite:   AccessMaskWriteDACL | AccessMaskWriteOwner,
			AccessMaskGenericExecute: AccessMaskSynchronize,
			AccessMaskGenericAll:     0xFFFFFFFF,
		},
	}
}

// AccessCheck simulates the Windows access check algorithm
// Returns whether the requested access is granted and additional details
func AccessCheck(securityDescriptor *NtSecurityDescriptor, token *TokenUser, 
	desiredAccess uint32, options *AccessCheckOptions) *AccessCheckResult {
	
	result := &AccessCheckResult{
		Granted: false,
		Reason:  "",
		Access:  0,
		Details: make([]CheckDetails, 0),
	}
	
	if options == nil {
		options = DefaultAccessCheckOptions()
	}
	
	// Map generic access rights if provided
	mappedAccess := MapGenericAccess(desiredAccess, options.GenericMapping)
	
	// Check integrity level policy if enabled
	if options.CheckIntegrity {
		integrityCheck := options.SubjectIntegrity.CheckAccess(
			options.ObjectIntegrity,
			options.IntegrityPolicy,
			mappedAccess)
		
		result.Details = append(result.Details, CheckDetails{
			Step:        "IntegrityLevel",
			Description: fmt.Sprintf("Checking if integrity level %s can access %s with policy %d",
				options.SubjectIntegrity, options.ObjectIntegrity, options.IntegrityPolicy),
			Outcome: integrityCheck,
		})
		
		if !integrityCheck {
			result.Reason = "Access denied by integrity level policy"
			return result
		}
	}
	
	// Check if the requested resource has a DACL
	if len(securityDescriptor.DACL.Aces) == 0 {
		// No DACL means full access (Windows rule)
		result.Granted = true
		result.Reason = "No DACL present (full access)"
		result.Access = mappedAccess
		
		result.Details = append(result.Details, CheckDetails{
			Step:        "EmptyDACL",
			Description: "No DACL present; full access granted",
			Outcome:     true,
		})
		
		return result
	}
	
	// Check owner access - owner always has READ_CONTROL and WRITE_DAC rights
	isOwner := token.UserSID.String() == securityDescriptor.Owner.String()
	ownerRights := uint32(AccessMaskReadControl | AccessMaskWriteDACL)
	
	result.Details = append(result.Details, CheckDetails{
		Step:        "OwnerCheck",
		Description: fmt.Sprintf("Checking if user is owner: %v", isOwner),
		Outcome:     isOwner,
	})
	
	// If only requesting owner rights and user is owner, grant access
	if isOwner && (mappedAccess & ^ownerRights) == 0 {
		result.Granted = true
		result.Reason = "Access granted to owner"
		result.Access = mappedAccess & ownerRights
		
		result.Details = append(result.Details, CheckDetails{
			Step:        "OwnerRights",
			Description: "Access granted based on ownership",
			Outcome:     true,
		})
		
		return result
	}
	
	// Process ACEs in order (Windows processes ACEs until a match is found)
	grantedAccess := uint32(0)
	deniedAccess := uint32(0)
	
	// First process deny ACEs
	for i, ace := range securityDescriptor.DACL.Aces {
		// Skip non-deny ACEs in the first pass
		if ace.Header.Type != AceTypeAccessDenied {
			continue
		}
		
		// Check if this ACE applies to the token
		applies, reason := aceAppliesToToken(ace, token, options)
		
		result.Details = append(result.Details, CheckDetails{
			Step:        fmt.Sprintf("DenyACE[%d]", i),
			Description: fmt.Sprintf("Checking if deny ACE applies: %v - %s", applies, reason),
			Outcome:     applies,
		})
		
		if applies {
			// Map the ACE's access mask using the same mapping
			aceMappedAccess := MapGenericAccess(ace.AccessMask.Raw(), options.GenericMapping)
			
			// If any requested access is explicitly denied, deny the entire request
			// For debugging:
			// fmt.Printf("ACE denies: 0x%08X (mapped: 0x%08X), requested: 0x%08X\n", 
			//    ace.AccessMask.Raw(), aceMappedAccess, mappedAccess)
				
			if aceMappedAccess & mappedAccess != 0 {
				result.Reason = fmt.Sprintf("Access explicitly denied by ACE %d", i)
				deniedAccess |= (aceMappedAccess & mappedAccess)
				
				result.Details = append(result.Details, CheckDetails{
					Step:        fmt.Sprintf("DenyACE[%d]Match", i),
					Description: fmt.Sprintf("Access denied by ACE - access mask 0x%08X", aceMappedAccess & mappedAccess),
					Outcome:     false,
				})
				
				// If all requested access is denied, return immediately
				if deniedAccess == mappedAccess {
					ace := ace // Copy to avoid issues with loop variable in closures
					result.Ace = &ace
					return result
				}
			}
		}
	}
	
	// Then process allow ACEs
	for i, ace := range securityDescriptor.DACL.Aces {
		// Skip non-allow ACEs in the second pass
		if ace.Header.Type != AceTypeAccessAllowed {
			continue
		}
		
		// Check if this ACE applies to the token
		applies, reason := aceAppliesToToken(ace, token, options)
		
		result.Details = append(result.Details, CheckDetails{
			Step:        fmt.Sprintf("AllowACE[%d]", i),
			Description: fmt.Sprintf("Checking if allow ACE applies: %v - %s", applies, reason),
			Outcome:     applies,
		})
		
		if applies {
			// Map the ACE's access mask using the same mapping
			aceMappedAccess := MapGenericAccess(ace.AccessMask.Raw(), options.GenericMapping)
			
			// Mark any explicitly allowed access rights
			allowedByThisAce := aceMappedAccess & mappedAccess & ^deniedAccess
			
			// For debugging:
			// fmt.Printf("ACE allows: 0x%08X (mapped: 0x%08X), requested: 0x%08X, denied: 0x%08X, allowed: 0x%08X\n", 
			//    ace.AccessMask.Raw(), aceMappedAccess, mappedAccess, deniedAccess, allowedByThisAce)
			
			if allowedByThisAce != 0 {
				grantedAccess |= allowedByThisAce
				
				result.Details = append(result.Details, CheckDetails{
					Step:        fmt.Sprintf("AllowACE[%d]Match", i),
					Description: fmt.Sprintf("Access allowed by ACE - access mask 0x%08X", allowedByThisAce),
					Outcome:     true,
				})
				
				// If all requested access is granted, we can return immediately
				if (grantedAccess | deniedAccess) == mappedAccess {
					break
				}
			}
		}
	}
	
	// Determine final access
	remainingAccess := mappedAccess & ^(grantedAccess | deniedAccess)
	
	// For debugging:
	// fmt.Printf("Final: requested=%08X, granted=%08X, denied=%08X, unmatched=%08X\n",
	//    mappedAccess, grantedAccess, deniedAccess, remainingAccess)
	
	if remainingAccess == 0 && grantedAccess == mappedAccess {
		// All requested access was granted
		result.Granted = true
		result.Reason = "Access granted by ACL"
		result.Access = grantedAccess
		
		result.Details = append(result.Details, CheckDetails{
			Step:        "FinalDecision",
			Description: "All requested access rights were granted",
			Outcome:     true,
		})
	} else {
		// Some access was not granted
		result.Granted = false
		
		if deniedAccess != 0 {
			result.Reason = "Some requested access was explicitly denied"
		} else {
			result.Reason = "Some requested access was not granted by any ACE"
		}
		
		result.Access = grantedAccess
		
		result.Details = append(result.Details, CheckDetails{
			Step:        "FinalDecision",
			Description: fmt.Sprintf(
				"Access partially granted: requested=%08X, granted=%08X, denied=%08X, unmatched=%08X",
				mappedAccess, grantedAccess, deniedAccess, remainingAccess),
			Outcome: false,
		})
	}
	
	return result
}

// aceAppliesToToken determines if an ACE applies to the given security token
func aceAppliesToToken(ace ACE, token *TokenUser, options *AccessCheckOptions) (bool, string) {
	// Get the SID from the ACE
	var aceSID SID
	
	switch oa := ace.ObjectAce.(type) {
	case BasicAce:
		aceSID = oa.SecurityIdentifier
	case AdvancedAce:
		aceSID = oa.SecurityIdentifier
		
		// Check if this is an object ACE and we need to check object types
		if !options.IgnoreObjectType {
			// If this is an Object ACE, further checks for object type would be done here
			// This would involve checking if the requested object's type matches the ACE's object type
			// For this implementation, we're simplifying by ignoring object types if requested
		}
	default:
		return false, "Unknown ACE object type"
	}
	
	// Check for well-known SIDs
	aceSIDStr := aceSID.String()
	
	// For debugging:
	// fmt.Printf("Checking ACE SID: %s vs user SID: %s\n", aceSIDStr, token.UserSID.String())
	// fmt.Printf("User groups: %v\n", token.Groups)
	
	// Everyone (S-1-1-0) always matches all tokens
	if aceSIDStr == "S-1-1-0" {
		return true, "Everyone SID matches all tokens"
	}
	
	// Check if the SID matches the user directly
	if aceSIDStr == token.UserSID.String() {
		return true, "Directly matches user SID"
	}
	
	// Check if the SID matches any of the user's groups
	for _, group := range token.Groups {
		groupStr := group.String()
		// For debugging:
		// fmt.Printf("  Comparing to group: %s\n", groupStr)
		if aceSIDStr == groupStr {
			return true, "Matches a group SID"
		}
	}
	
	return false, "No SID match found"
}

// MapGenericAccess maps generic access rights to specific rights
func MapGenericAccess(access uint32, mapping map[uint32]uint32) uint32 {
	if mapping == nil {
		return access
	}
	
	result := uint32(0)
	
	// Check each generic right
	genericRights := []uint32{
		AccessMaskGenericRead,
		AccessMaskGenericWrite,
		AccessMaskGenericExecute,
		AccessMaskGenericAll,
	}
	
	// Map any generic rights present in the access mask
	for _, genericRight := range genericRights {
		if access&genericRight != 0 {
			if specificRights, ok := mapping[genericRight]; ok {
				result |= specificRights
				// Remove the generic right bit
				access &= ^genericRight
			}
		}
	}
	
	// Add any remaining specific rights
	result |= access
	
	// If we're mapping a generic right but there's no specific mapping,
	// keep the generic right as-is to allow direct comparisons
	if result == 0 && access != 0 {
		return access
	}
	
	return result
}