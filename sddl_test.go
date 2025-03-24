package winacl_test

import (
	"testing"

	"github.com/audibleblink/go-winacl"

	"github.com/stretchr/testify/require"
)

func TestACERightsString(t *testing.T) {
	r := require.New(t)

	// Create an ACE with specific permissions
	ace := winacl.ACE{
		AccessMask: winacl.ACEAccessMask{Value: winacl.AccessMaskGenericRead | winacl.AccessMaskReadControl},
	}

	// Test RightsString method
	s := ace.RightsString()
	r.Contains(s, "GR") // Generic Read
	r.Contains(s, "RC") // Read Control
}

func TestACEHeaderSDDLFlags(t *testing.T) {
	r := require.New(t)

	// Create an ACE header with specific flags
	header := winacl.ACEHeader{
		Flags: winacl.ACEHeaderFlagsObjectInheritAce | winacl.ACEHeaderFlagsContainerInheritAce,
	}

	// Test SDDLFlags method
	s := header.SDDLFlags()
	r.Contains(s, "OI") // Object Inherit
	r.Contains(s, "CI") // Container Inherit
}

func TestACEToSDDL(t *testing.T) {
	r := require.New(t)
	
	// Create a basic ACE since the test data might not be available
	header := winacl.ACEHeader{
		Type:  winacl.AceTypeAccessAllowed,
		Flags: winacl.ACEHeaderFlagsObjectInheritAce,
		Size:  20,
	}
	
	accessMask := winacl.ACEAccessMask{Value: winacl.AccessMaskGenericRead}
	
	sid := winacl.SID{
		Revision:       1,
		NumAuthorities: 1,
		Authority:      []byte{0, 0, 0, 0, 0, 5},
		SubAuthorities: []uint32{18},
	}
	
	basicAce := winacl.BasicAce{SecurityIdentifier: sid}
	
	ace := winacl.ACE{
		Header:     header,
		AccessMask: accessMask,
		ObjectAce:  basicAce,
	}

	// Test ToSDDL method
	sddl := ace.ToSDDL()
	r.Contains(sddl, "(")
	r.Contains(sddl, ";")
	r.Contains(sddl, ")")
	// Expect SDDL format: (AceType;AceFlags;Rights;ObjectGUID;InheritedObjectGUID;AccountSID)
	r.Regexp(`\([A-Z]+;[A-Z]*;[A-Z]*;[^;]*;[^;]*;[^;)]*\)`, sddl)
}

func TestACLToSDDL(t *testing.T) {
	r := require.New(t)
	
	// Create an ACL with a basic ACE
	header := winacl.ACEHeader{
		Type:  winacl.AceTypeAccessAllowed,
		Flags: winacl.ACEHeaderFlagsObjectInheritAce,
		Size:  20,
	}
	
	accessMask := winacl.ACEAccessMask{Value: winacl.AccessMaskGenericRead}
	
	sid := winacl.SID{
		Revision:       1,
		NumAuthorities: 1,
		Authority:      []byte{0, 0, 0, 0, 0, 5},
		SubAuthorities: []uint32{18},
	}
	
	basicAce := winacl.BasicAce{SecurityIdentifier: sid}
	
	ace := winacl.ACE{
		Header:     header,
		AccessMask: accessMask,
		ObjectAce:  basicAce,
	}
	
	aclHeader := winacl.ACLHeader{
		Revision: 1,
		AceCount: 1,
		Size: 20,
	}
	
	acl := winacl.ACL{
		Header: aclHeader,
		Aces: []winacl.ACE{ace},
	}

	// Test ToSDDL method with empty flags
	sddl := acl.ToSDDL("")
	r.Contains(sddl, "D:")
	r.Contains(sddl, "(") // Contains at least one ACE

	// Test ToSDDL method with flags
	sddl = acl.ToSDDL("P")
	r.Contains(sddl, "D:P")
}

func TestNtSecurityDescriptorHeaderToSDDL(t *testing.T) {
	r := require.New(t)

	// Create a header with specific control flags
	header := winacl.NtSecurityDescriptorHeader{
		Control: uint16(winacl.ControlDACLProtected | winacl.ControlDACLAutoInherit),
	}

	// Test ToSDDL method
	sddl := header.ToSDDL()
	r.Contains(sddl, "P")  // Protected
	r.Contains(sddl, "AI") // Auto Inherit
}

func TestNtSecurityDescriptorToSDDL(t *testing.T) {
	r := require.New(t)
	
	// Create a security descriptor
	header := winacl.NtSecurityDescriptorHeader{
		Revision: 1,
		Control: uint16(winacl.ControlDACLProtected),
		OffsetOwner: 20,
		OffsetGroup: 40,
	}
	
	// Create owner SID
	ownerSid := winacl.SID{
		Revision:       1,
		NumAuthorities: 1,
		Authority:      []byte{0, 0, 0, 0, 0, 5},
		SubAuthorities: []uint32{18},
	}
	
	// Create group SID
	groupSid := winacl.SID{
		Revision:       1,
		NumAuthorities: 1,
		Authority:      []byte{0, 0, 0, 0, 0, 5},
		SubAuthorities: []uint32{32},
	}
	
	// Create an ACE for DACL
	aceHeader := winacl.ACEHeader{
		Type:  winacl.AceTypeAccessAllowed,
		Flags: winacl.ACEHeaderFlagsObjectInheritAce,
		Size:  20,
	}
	
	accessMask := winacl.ACEAccessMask{Value: winacl.AccessMaskGenericRead}
	basicAce := winacl.BasicAce{SecurityIdentifier: ownerSid}
	
	ace := winacl.ACE{
		Header:     aceHeader,
		AccessMask: accessMask,
		ObjectAce:  basicAce,
	}
	
	// Create ACL
	aclHeader := winacl.ACLHeader{
		Revision: 1,
		AceCount: 1,
		Size: 20,
	}
	
	acl := winacl.ACL{
		Header: aclHeader,
		Aces: []winacl.ACE{ace},
	}
	
	// Create security descriptor
	sd := winacl.NtSecurityDescriptor{
		Header: header,
		Owner: ownerSid,
		Group: groupSid,
		DACL: acl,
	}

	// Test ToSDDL method
	sddl := sd.ToSDDL()
	r.Contains(sddl, "O:")  // Owner
	r.Contains(sddl, "G:")  // Group
	r.Contains(sddl, "D:")  // DACL
}
