package winacl

import (
	"testing"
)

func TestAccessCheck(t *testing.T) {
	// Create a set of common SIDs for testing
	adminSID, _ := NewSIDFromString("S-1-5-32-544") // Administrators
	userSID, _ := NewSIDFromString("S-1-5-21-1234567890-1234567890-1234567890-1001") // Regular user
	systemSID, _ := NewSIDFromString("S-1-5-18") // System
	everyoneSID, _ := NewSIDFromString("S-1-1-0") // Everyone

	// Test case 1: Empty DACL - Full access
	t.Run("EmptyDACL", func(t *testing.T) {
		// Create a security descriptor with an empty DACL
		sd := &NtSecurityDescriptor{
			Owner: adminSID,
			Group: adminSID,
			DACL:  ACL{},
		}

		// Create a token for a regular user
		token := NewTokenUser(userSID, []SID{everyoneSID})

		// Request read access
		result := AccessCheck(sd, token, AccessMaskGenericRead, nil)

		// Empty DACL should grant full access
		if !result.Granted {
			t.Errorf("Empty DACL should grant access, but got: %s", result.Reason)
		}
	})

	// Test case 2: Owner access rights
	t.Run("OwnerAccess", func(t *testing.T) {
		// Create a security descriptor with a DACL that has no ACEs for the user
		sd := &NtSecurityDescriptor{
			Owner: userSID, // User is the owner
			Group: adminSID,
			DACL: ACL{
				Aces: []ACE{
					// No ACEs that would grant access to the user
				},
			},
		}

		// Create a token for the user (who is the owner)
		token := NewTokenUser(userSID, []SID{everyoneSID})

		// Request owner-specific rights
		result := AccessCheck(sd, token, AccessMaskReadControl|AccessMaskWriteDACL, nil)

		// Owner should have these rights
		if !result.Granted {
			t.Errorf("Owner should have read control and write DACL rights, but got: %s", result.Reason)
		}
	})

	// Test case 3: Explicit allow ACE
	t.Run("ExplicitAllow", func(t *testing.T) {
		// Create an ACE that allows read access to everyone
		allowAce := NewAccessAllowedACE(everyoneSID, AccessMaskGenericRead)

		// Create a security descriptor with a DACL containing the allow ACE
		sd := &NtSecurityDescriptor{
			Owner: adminSID,
			Group: adminSID,
			DACL: ACL{
				Aces: []ACE{allowAce},
			},
		}

		// Create a token for a regular user
		token := NewTokenUser(userSID, []SID{everyoneSID})

		// Request read access
		result := AccessCheck(sd, token, AccessMaskGenericRead, nil)

		// Access should be granted
		if !result.Granted {
			t.Errorf("Access should be granted via allow ACE, but got: %s", result.Reason)
		}
	})

	// Test case 4: Explicit deny ACE
	t.Run("ExplicitDeny", func(t *testing.T) {
		// Create an ACE that denies write access to everyone
		denyAce := NewAccessDeniedACE(everyoneSID, AccessMaskGenericWrite)
		
		// Create an ACE that allows read access to everyone
		allowAce := NewAccessAllowedACE(everyoneSID, AccessMaskGenericRead)

		// Create a security descriptor with a DACL containing both ACEs
		sd := &NtSecurityDescriptor{
			Owner: adminSID,
			Group: adminSID,
			DACL: ACL{
				Aces: []ACE{denyAce, allowAce},
			},
		}

		// Create a token for a regular user
		token := NewTokenUser(userSID, []SID{everyoneSID})

		// Request write access
		result := AccessCheck(sd, token, AccessMaskGenericWrite, nil)

		// Access should be denied
		if result.Granted {
			t.Errorf("Access should be denied via deny ACE, but was granted")
		}

		// Request read access
		result = AccessCheck(sd, token, AccessMaskGenericRead, nil)

		// Access should be granted
		if !result.Granted {
			t.Errorf("Read access should be granted, but got: %s", result.Reason)
		}
	})

	// Test case 5: Deny ACE takes precedence over allow ACE
	t.Run("DenyTakesPrecedence", func(t *testing.T) {
		// Create an ACE that allows all access to the user
		allowAce := NewAccessAllowedACE(userSID, AccessMaskGenericAll)
		
		// Create an ACE that denies write access to everyone
		denyAce := NewAccessDeniedACE(everyoneSID, AccessMaskGenericWrite)

		// Create a security descriptor with a DACL containing both ACEs
		sd := &NtSecurityDescriptor{
			Owner: adminSID,
			Group: adminSID,
			DACL: ACL{
				Aces: []ACE{denyAce, allowAce},
			},
		}

		// Create a token for the user
		token := NewTokenUser(userSID, []SID{everyoneSID})

		// Request write access
		result := AccessCheck(sd, token, AccessMaskGenericWrite, nil)

		// Access should be denied, despite the allow ACE
		if result.Granted {
			t.Errorf("Access should be denied, deny ACE should take precedence, but was granted")
		}
	})

	// Test case 6: No matching ACE for the requested access
	t.Run("NoMatchingACE", func(t *testing.T) {
		// Create an ACE that allows read access
		allowAce := NewAccessAllowedACE(everyoneSID, AccessMaskGenericRead)

		// Create a security descriptor with a DACL containing the allow ACE
		sd := &NtSecurityDescriptor{
			Owner: adminSID,
			Group: adminSID,
			DACL: ACL{
				Aces: []ACE{allowAce},
			},
		}

		// Create a token for a regular user
		token := NewTokenUser(userSID, []SID{everyoneSID})

		// Request write access (which is not granted by any ACE)
		result := AccessCheck(sd, token, AccessMaskGenericWrite, nil)

		// Access should be denied
		if result.Granted {
			t.Errorf("Access should be denied when no ACE grants the requested access, but was granted")
		}
	})

	// Test case 7: Group membership
	t.Run("GroupMembership", func(t *testing.T) {
		// Create an ACE that allows read access to administrators
		allowAce := NewAccessAllowedACE(adminSID, AccessMaskGenericRead)

		// Create a security descriptor with a DACL containing the allow ACE
		sd := &NtSecurityDescriptor{
			Owner: systemSID,
			Group: adminSID,
			DACL: ACL{
				Aces: []ACE{allowAce},
			},
		}

		// Create a token for a user who is a member of the administrators group
		token := NewTokenUser(userSID, []SID{everyoneSID, adminSID})

		// Request read access
		result := AccessCheck(sd, token, AccessMaskGenericRead, nil)

		// Access should be granted due to group membership
		if !result.Granted {
			t.Errorf("Access should be granted via group membership, but got: %s", result.Reason)
		}
	})

	// Test case 8: Integrity level policy enforcement
	t.Run("IntegrityPolicy", func(t *testing.T) {
		// Create a security descriptor with an allow ACE for everyone that explicitly grants
		// both generic and specific rights to ensure proper mapping
		allowAce := NewAccessAllowedACE(
			everyoneSID, 
			AccessMaskGenericAll | AccessMaskReadControl | AccessMaskWriteDACL | 
			AccessMaskGenericRead | AccessMaskGenericWrite)
		
		sd := &NtSecurityDescriptor{
			Owner: adminSID,
			Group: adminSID,
			DACL: ACL{
				Aces: []ACE{allowAce},
			},
		}

		// Create a token for a low integrity user
		token := NewTokenUser(userSID, []SID{everyoneSID})

		// Create options that enforce integrity level checks with explicit mapping
		options := &AccessCheckOptions{
			CheckIntegrity:   true,
			IntegrityPolicy:  PolicyNoWriteUp,
			SubjectIntegrity: IntegrityLevelLow,
			ObjectIntegrity:  IntegrityLevelHigh,
			GenericMapping: map[uint32]uint32{
				AccessMaskGenericRead:    AccessMaskReadControl,
				AccessMaskGenericWrite:   AccessMaskWriteDACL,
				AccessMaskGenericExecute: AccessMaskSynchronize,
				AccessMaskGenericAll:     0xFFFFFFFF,
			},
		}

		// Request write access (should be denied by integrity policy)
		result := AccessCheck(sd, token, AccessMaskGenericWrite, options)

		// Access should be denied due to integrity policy
		if result.Granted {
			t.Errorf("Write access should be denied by integrity policy, but was granted")
		}

		// Request read access (should be allowed despite integrity level difference)
		result = AccessCheck(sd, token, AccessMaskGenericRead, options)

		// Read access should be granted
		if !result.Granted {
			t.Errorf("Read access should be granted despite integrity level difference, but got: %s", result.Reason)
		}

		// Now use a stricter policy that prevents read-up
		options.IntegrityPolicy = PolicyNoReadUp

		// Request read access again (should now be denied)
		result = AccessCheck(sd, token, AccessMaskGenericRead, options)

		// Access should be denied due to the stricter policy
		if result.Granted {
			t.Errorf("Read access should be denied by NoReadUp policy, but was granted")
		}
	})

	// Test case 9: Generic access mapping
	t.Run("GenericAccessMapping", func(t *testing.T) {
		// Create an ACE that allows specific rights (not generic)
		specificRights := uint32(AccessMaskReadControl | AccessMaskSynchronize)
		allowAce := NewAccessAllowedACE(everyoneSID, specificRights)
		
		sd := &NtSecurityDescriptor{
			Owner: adminSID,
			Group: adminSID,
			DACL: ACL{
				Aces: []ACE{allowAce},
			},
		}

		// Create a token for a regular user
		token := NewTokenUser(userSID, []SID{everyoneSID})

		// Create custom mapping
		options := &AccessCheckOptions{
			GenericMapping: map[uint32]uint32{
				AccessMaskGenericRead: AccessMaskReadControl,
				AccessMaskGenericExecute: AccessMaskSynchronize,
			},
		}

		// Request generic read (should map to read control, which is granted)
		result := AccessCheck(sd, token, AccessMaskGenericRead, options)

		// Access should be granted after mapping
		if !result.Granted {
			t.Errorf("Access should be granted after generic mapping, but got: %s", result.Reason)
		}

		// Request generic write (should map to write DACL, which is not granted)
		result = AccessCheck(sd, token, AccessMaskGenericWrite, options)

		// Access should be denied
		if result.Granted {
			t.Errorf("Write access should be denied after generic mapping, but was granted")
		}
	})

	// Test case 10: Partially granted access
	t.Run("PartialAccess", func(t *testing.T) {
		// Create an ACE that allows only read access
		allowAce := NewAccessAllowedACE(everyoneSID, AccessMaskGenericRead | AccessMaskReadControl)
		
		sd := &NtSecurityDescriptor{
			Owner: adminSID,
			Group: adminSID,
			DACL: ACL{
				Aces: []ACE{allowAce},
			},
		}

		// Create a token for a regular user
		token := NewTokenUser(userSID, []SID{everyoneSID})

		// Create mapping options
		options := &AccessCheckOptions{
			GenericMapping: map[uint32]uint32{
				AccessMaskGenericRead:    AccessMaskReadControl,
				AccessMaskGenericWrite:   AccessMaskWriteDACL,
				AccessMaskGenericExecute: AccessMaskSynchronize,
				AccessMaskGenericAll:     0xFFFFFFFF,
			},
		}

		// Request both read and write access
		result := AccessCheck(sd, token, AccessMaskGenericRead|AccessMaskGenericWrite, options)

		// Overall access should be denied because not all requested access was granted
		if result.Granted {
			t.Errorf("Access should be partially denied, but was fully granted")
		}

		// Check that read control (mapped from generic read) was granted
		if result.Access&AccessMaskReadControl == 0 {
			t.Errorf("Read control access should be granted within partial access")
		}

		// The write control (mapped from generic write) should be denied
		if result.Access&AccessMaskWriteDACL != 0 {
			t.Errorf("Write DACL access should be denied within partial access")
		}
	})
}

func TestMapGenericAccess(t *testing.T) {
	// Test case 1: Basic mapping
	t.Run("BasicMapping", func(t *testing.T) {
		mapping := map[uint32]uint32{
			AccessMaskGenericRead:    AccessMaskReadControl,
			AccessMaskGenericWrite:   AccessMaskWriteDACL,
			AccessMaskGenericExecute: AccessMaskSynchronize,
			AccessMaskGenericAll:     0xFFFF,
		}

		result := MapGenericAccess(AccessMaskGenericRead, mapping)
		if result != AccessMaskReadControl {
			t.Errorf("Expected generic read to map to read control, got: 0x%08X", result)
		}
	})

	// Test case 2: Combined generic and specific rights
	t.Run("CombinedRights", func(t *testing.T) {
		mapping := map[uint32]uint32{
			AccessMaskGenericRead:  AccessMaskReadControl,
			AccessMaskGenericWrite: AccessMaskWriteDACL,
		}

		// Both generic and specific rights
		combined := uint32(AccessMaskGenericRead | AccessMaskDelete)
		result := MapGenericAccess(combined, mapping)
		
		// Should map generic read to read control and preserve delete
		expected := uint32(AccessMaskReadControl | AccessMaskDelete)
		if result != expected {
			t.Errorf("Expected 0x%08X, got: 0x%08X", expected, result)
		}
	})

	// Test case 3: Multiple generic rights
	t.Run("MultipleGenericRights", func(t *testing.T) {
		mapping := map[uint32]uint32{
			AccessMaskGenericRead:    AccessMaskReadControl,
			AccessMaskGenericWrite:   AccessMaskWriteDACL,
			AccessMaskGenericExecute: AccessMaskSynchronize,
		}

		// Multiple generic rights
		multiple := uint32(AccessMaskGenericRead | AccessMaskGenericWrite)
		result := MapGenericAccess(multiple, mapping)
		
		// Should map both generics to their specific rights
		expected := uint32(AccessMaskReadControl | AccessMaskWriteDACL)
		if result != expected {
			t.Errorf("Expected 0x%08X, got: 0x%08X", expected, result)
		}
	})

	// Test case 4: Nil mapping
	t.Run("NilMapping", func(t *testing.T) {
		// Passing nil should return the input unchanged
		access := uint32(AccessMaskGenericRead | AccessMaskDelete)
		result := MapGenericAccess(access, nil)
		
		if result != access {
			t.Errorf("Expected unchanged access mask with nil mapping")
		}
	})

	// Test case 5: Empty mapping
	t.Run("EmptyMapping", func(t *testing.T) {
		// Empty mapping should handle generic rights that aren't in the map
		mapping := map[uint32]uint32{}
		access := uint32(AccessMaskGenericRead | AccessMaskDelete)
		result := MapGenericAccess(access, mapping)
		
		// Should leave generic read intact and preserve delete
		if result != access {
			t.Errorf("Expected unchanged access mask with empty mapping")
		}
	})
}

func TestAceAppliesToToken(t *testing.T) {
	// Create a set of common SIDs for testing
	adminSID, _ := NewSIDFromString("S-1-5-32-544") // Administrators
	userSID, _ := NewSIDFromString("S-1-5-21-1234567890-1234567890-1234567890-1001") // Regular user
	everyoneSID, _ := NewSIDFromString("S-1-1-0") // Everyone

	// Test case 1: Everyone SID should match any token
	t.Run("EveryoneMatches", func(t *testing.T) {
		ace := NewAccessAllowedACE(everyoneSID, AccessMaskGenericRead)
		token := NewTokenUser(userSID, []SID{})
		options := DefaultAccessCheckOptions()

		applies, _ := aceAppliesToToken(ace, token, options)
		if !applies {
			t.Errorf("Everyone SID should match any token")
		}
	})

	// Test case 2: User SID match
	t.Run("UserSIDMatch", func(t *testing.T) {
		ace := NewAccessAllowedACE(userSID, AccessMaskGenericRead)
		token := NewTokenUser(userSID, []SID{adminSID})
		options := DefaultAccessCheckOptions()

		applies, _ := aceAppliesToToken(ace, token, options)
		if !applies {
			t.Errorf("User SID should match the token's user SID")
		}
	})

	// Test case 3: Group SID match
	t.Run("GroupSIDMatch", func(t *testing.T) {
		ace := NewAccessAllowedACE(adminSID, AccessMaskGenericRead)
		token := NewTokenUser(userSID, []SID{adminSID})
		options := DefaultAccessCheckOptions()

		applies, _ := aceAppliesToToken(ace, token, options)
		if !applies {
			t.Errorf("Group SID should match one of the token's group SIDs")
		}
	})

	// Test case 4: No match
	t.Run("NoMatch", func(t *testing.T) {
		ace := NewAccessAllowedACE(adminSID, AccessMaskGenericRead)
		token := NewTokenUser(userSID, []SID{everyoneSID})
		options := DefaultAccessCheckOptions()

		applies, _ := aceAppliesToToken(ace, token, options)
		if applies {
			t.Errorf("ACE should not apply to token with no matching SIDs")
		}
	})
}

func TestIntegrityLevelCheck(t *testing.T) {
	// Test case 1: Higher integrity should access lower integrity
	t.Run("HigherToLower", func(t *testing.T) {
		// Create a security descriptor with an allow ACE for everyone with explicit access masks
		allowAce := NewAccessAllowedACE(
			NewSIDFromStringOrPanic("S-1-1-0"), 
			AccessMaskGenericAll | AccessMaskGenericWrite | AccessMaskGenericRead | 
			AccessMaskWriteDACL | AccessMaskReadControl | AccessMaskDelete | 0xFFFF)
		
		sd := &NtSecurityDescriptor{
			Owner: NewSIDFromStringOrPanic("S-1-5-18"), // System
			Group: NewSIDFromStringOrPanic("S-1-5-32-544"), // Administrators
			DACL: ACL{
				Aces: []ACE{allowAce},
			},
		}

		// Create a token for a high integrity user accessing a medium integrity object
		token := NewTokenUser(
			NewSIDFromStringOrPanic("S-1-5-21-1234567890-1234567890-1234567890-1001"),
			[]SID{NewSIDFromStringOrPanic("S-1-1-0")}, // Everyone
		)

		options := &AccessCheckOptions{
			CheckIntegrity:   true,
			IntegrityPolicy:  PolicyNoWriteUp,
			SubjectIntegrity: IntegrityLevelHigh,
			ObjectIntegrity:  IntegrityLevelMedium,
			GenericMapping: map[uint32]uint32{
				AccessMaskGenericRead:    AccessMaskReadControl,
				AccessMaskGenericWrite:   AccessMaskWriteDACL,
				AccessMaskGenericExecute: AccessMaskSynchronize,
				AccessMaskGenericAll:     0xFFFFFFFF,
			},
		}

		result := AccessCheck(sd, token, AccessMaskGenericWrite, options)

		// Access should be granted because higher integrity can access lower
		if !result.Granted {
			t.Errorf("Higher integrity should be able to write to lower integrity, but got: %s", result.Reason)
		}
	})

	// Test case 2: Lower integrity should not write up
	t.Run("LowerToHigherWriteBlocked", func(t *testing.T) {
		// Create a security descriptor with an allow ACE for everyone with explicit access masks
		allowAce := NewAccessAllowedACE(
			NewSIDFromStringOrPanic("S-1-1-0"), 
			AccessMaskGenericAll | AccessMaskGenericWrite | AccessMaskGenericRead | 
			AccessMaskWriteDACL | AccessMaskReadControl | AccessMaskDelete | 0xFFFF)
		
		sd := &NtSecurityDescriptor{
			Owner: NewSIDFromStringOrPanic("S-1-5-18"), // System
			Group: NewSIDFromStringOrPanic("S-1-5-32-544"), // Administrators
			DACL: ACL{
				Aces: []ACE{allowAce},
			},
		}

		// Create a token for a low integrity user accessing a high integrity object
		token := NewTokenUser(
			NewSIDFromStringOrPanic("S-1-5-21-1234567890-1234567890-1234567890-1001"),
			[]SID{NewSIDFromStringOrPanic("S-1-1-0")}, // Everyone
		)

		options := &AccessCheckOptions{
			CheckIntegrity:   true,
			IntegrityPolicy:  PolicyNoWriteUp,
			SubjectIntegrity: IntegrityLevelLow,
			ObjectIntegrity:  IntegrityLevelHigh,
			GenericMapping: map[uint32]uint32{
				AccessMaskGenericRead:    AccessMaskReadControl,
				AccessMaskGenericWrite:   AccessMaskWriteDACL,
				AccessMaskGenericExecute: AccessMaskSynchronize,
				AccessMaskGenericAll:     0xFFFFFFFF,
			},
		}

		result := AccessCheck(sd, token, AccessMaskGenericWrite, options)

		// Write access should be denied due to integrity policy
		if result.Granted {
			t.Errorf("Low integrity should not be able to write to high integrity")
		}
	})

	// Test case 3: Same integrity level should pass
	t.Run("SameIntegrityLevel", func(t *testing.T) {
		// Create a security descriptor with an allow ACE for everyone with explicit access masks
		allowAce := NewAccessAllowedACE(
			NewSIDFromStringOrPanic("S-1-1-0"), 
			AccessMaskGenericAll | AccessMaskGenericWrite | AccessMaskGenericRead | 
			AccessMaskWriteDACL | AccessMaskReadControl | AccessMaskDelete | 0xFFFF)
		
		sd := &NtSecurityDescriptor{
			Owner: NewSIDFromStringOrPanic("S-1-5-18"), // System
			Group: NewSIDFromStringOrPanic("S-1-5-32-544"), // Administrators
			DACL: ACL{
				Aces: []ACE{allowAce},
			},
		}

		// Create a token for a medium integrity user accessing a medium integrity object
		token := NewTokenUser(
			NewSIDFromStringOrPanic("S-1-5-21-1234567890-1234567890-1234567890-1001"),
			[]SID{NewSIDFromStringOrPanic("S-1-1-0")}, // Everyone
		)

		options := &AccessCheckOptions{
			CheckIntegrity:   true,
			IntegrityPolicy:  PolicyNoWriteUp | PolicyNoReadUp | PolicyNoExecuteUp,
			SubjectIntegrity: IntegrityLevelMedium,
			ObjectIntegrity:  IntegrityLevelMedium,
			GenericMapping: map[uint32]uint32{
				AccessMaskGenericRead:    AccessMaskReadControl,
				AccessMaskGenericWrite:   AccessMaskWriteDACL,
				AccessMaskGenericExecute: AccessMaskSynchronize,
				AccessMaskGenericAll:     0xFFFFFFFF,
			},
		}

		result := AccessCheck(sd, token, AccessMaskGenericAll, options)

		// Access should be granted at same integrity level regardless of policy
		if !result.Granted {
			t.Errorf("Same integrity level should be able to access each other, but got: %s", result.Reason)
		}
	})
}

// Helper function to create a panic-free SID from string
func NewSIDFromStringOrPanic(sidString string) SID {
	sid, err := NewSIDFromString(sidString)
	if err != nil {
		panic(err)
	}
	return sid
}

// Helper functions for creating ACEs more easily
func NewAccessAllowedACE(sid SID, value uint32) ACE {
	return ACE{
		Header: ACEHeader{
			Type: AceTypeAccessAllowed,
			Size: 8 + uint16(8 + 4*int(sid.NumAuthorities)), // Header + access mask + SID size
		},
		AccessMask: ACEAccessMask{Value: value},
		ObjectAce: BasicAce{
			SecurityIdentifier: sid,
		},
	}
}

func NewAccessDeniedACE(sid SID, value uint32) ACE {
	return ACE{
		Header: ACEHeader{
			Type: AceTypeAccessDenied,
			Size: 8 + uint16(8 + 4*int(sid.NumAuthorities)), // Header + access mask + SID size
		},
		AccessMask: ACEAccessMask{Value: value},
		ObjectAce: BasicAce{
			SecurityIdentifier: sid,
		},
	}
}
