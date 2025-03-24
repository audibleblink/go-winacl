package winacl_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/audibleblink/go-winacl"

	"github.com/stretchr/testify/require"
)

func TestACEAccessMaskMethods(t *testing.T) {
	r := require.New(t)

	// Create an access mask with specific permissions
	acm := winacl.ACEAccessMask{Value: winacl.AccessMaskGenericRead | winacl.AccessMaskReadControl}

	t.Run("Raw returns the correct value", func(t *testing.T) {
		value := acm.Raw()
		r.Equal(uint32(winacl.AccessMaskGenericRead|winacl.AccessMaskReadControl), value)
	})

	t.Run("String returns a space-separated list of permissions", func(t *testing.T) {
		s := acm.String()
		r.Contains(s, "GENERIC_READ")
		r.Contains(s, "READ_CONTROL")
	})

	t.Run("StringSlice returns a slice of permission strings", func(t *testing.T) {
		perms := acm.StringSlice()
		r.Contains(perms, "GENERIC_READ")
		r.Contains(perms, "READ_CONTROL")
		r.Len(perms, 2)
	})
}

func TestACEMethods(t *testing.T) {
	r := require.New(t)
	
	t.Run("GetType returns the correct ACE type", func(t *testing.T) {
		// Create a basic ACE
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
		
		acetype := ace.GetType()
		r.Equal(winacl.AceTypeAccessAllowed, acetype)
	})

	t.Run("GetTypeString returns a string representation of type", func(t *testing.T) {
		header := winacl.ACEHeader{
			Type:  winacl.AceTypeAccessAllowed,
			Flags: winacl.ACEHeaderFlagsObjectInheritAce,
		}
		
		ace := winacl.ACE{
			Header: header,
		}
		
		typeStr := ace.GetTypeString()
		r.Equal("ACCESS_ALLOWED", typeStr)
	})

	t.Run("String returns formatted representation for BasicAce", func(t *testing.T) {
		// Create a basic ACE
		header := winacl.ACEHeader{
			Type:  winacl.AceTypeAccessAllowed,
			Flags: winacl.ACEHeaderFlagsObjectInheritAce,
			Size:  20,
		}
		
		accessMask := winacl.ACEAccessMask{Value: winacl.AccessMaskGenericRead | winacl.AccessMaskReadControl}
		
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
		
		s := ace.String()
		r.Contains(s, "AceType: ACCESS_ALLOWED")
		r.Contains(s, "Flags: OBJECT_INHERIT_ACE")
		r.Contains(s, "Permissions:")
		r.Contains(s, "GENERIC_READ")
		r.Contains(s, "READ_CONTROL")
		r.Contains(s, "SID: S-1-5-18")
	})
	
	t.Run("String returns formatted representation for AdvancedAce with ObjectType", func(t *testing.T) {
		// Create an AdvancedAce with ObjectType present flag
		guid := winacl.GUID{
			Data1: 0x12345678,
			Data2: 0x1234,
			Data3: 0x5678,
			Data4: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		}
		
		ace := winacl.ACE{
			Header: winacl.ACEHeader{
				Type: winacl.AceTypeAccessAllowedObject,
			},
			AccessMask: winacl.ACEAccessMask{
				Value: winacl.AccessMaskGenericRead,
			},
			ObjectAce: winacl.AdvancedAce{
				Flags:              winacl.ACEInheritanceFlagsObjectTypePresent,
				ObjectType:         guid,
				SecurityIdentifier: winacl.SID{
					Revision:       1,
					NumAuthorities: 1,
					Authority:      []byte{0, 0, 0, 0, 0, 5}, // NT Authority
					SubAuthorities: []uint32{18},              // Local System
				},
			},
		}
		
		s := ace.String()
		r.Contains(s, "AceType: ACCESS_ALLOWED_OBJECT")
		r.Contains(s, "ObjectType:")
		r.Contains(s, "Permissions:")
		r.Contains(s, "GENERIC_READ")
		r.Contains(s, "SID: S-1-5-18")
	})
	
	t.Run("String returns formatted representation for AdvancedAce with InheritedObjectType", func(t *testing.T) {
		// Create an AdvancedAce with InheritedObjectType present flag
		guid := winacl.GUID{
			Data1: 0x12345678,
			Data2: 0x1234,
			Data3: 0x5678,
			Data4: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		}
		
		ace := winacl.ACE{
			Header: winacl.ACEHeader{
				Type: winacl.AceTypeAccessAllowedObject,
			},
			AccessMask: winacl.ACEAccessMask{
				Value: winacl.AccessMaskGenericRead,
			},
			ObjectAce: winacl.AdvancedAce{
				Flags:               winacl.ACEInheritanceFlagsInheritedObjectTypePresent,
				InheritedObjectType: guid,
				SecurityIdentifier:  winacl.SID{
					Revision:       1,
					NumAuthorities: 1,
					Authority:      []byte{0, 0, 0, 0, 0, 5}, // NT Authority
					SubAuthorities: []uint32{18},              // Local System
				},
			},
		}
		
		s := ace.String()
		r.Contains(s, "AceType: ACCESS_ALLOWED_OBJECT")
		r.Contains(s, "InheritedObjectType:")
		r.Contains(s, "Permissions:")
		r.Contains(s, "GENERIC_READ")
		r.Contains(s, "SID: S-1-5-18")
	})
}

func TestACEHeaderFlagsString(t *testing.T) {
	r := require.New(t)
	header := winacl.ACEHeader{
		Type:  winacl.AceTypeAccessAllowed,
		Flags: winacl.ACEHeaderFlagsObjectInheritAce | winacl.ACEHeaderFlagsContainerInheritAce,
		Size:  20,
	}

	flagsStr := header.FlagsString()
	r.Contains(flagsStr, "OBJECT_INHERIT_ACE")
	r.Contains(flagsStr, "CONTAINER_INHERIT_ACE")
}

func TestAdvancedAceFlagsString(t *testing.T) {
	r := require.New(t)

	aceDummy := winacl.AdvancedAce{
		Flags: winacl.ACEInheritanceFlagsObjectTypePresent,
	}

	flagsStr := aceDummy.FlagsString()
	r.Contains(flagsStr, "ACE_OBJECT_TYPE_PRESENT")
}

func TestNewACEHeader(t *testing.T) {
	r := require.New(t)

	t.Run("Creates an ACE header from a valid buffer", func(t *testing.T) {
		// Prepare a buffer with valid ACE header data
		header := winacl.ACEHeader{
			Type:  winacl.AceTypeAccessAllowed,
			Flags: winacl.ACEHeaderFlagsObjectInheritAce,
			Size:  20,
		}
		buf := bytes.Buffer{}
		err := binary.Write(&buf, binary.LittleEndian, &header)
		r.NoError(err)

		// Parse the buffer
		parsedHeader, err := winacl.NewACEHeader(&buf)
		r.NoError(err)
		r.Equal(header.Type, parsedHeader.Type)
		r.Equal(header.Flags, parsedHeader.Flags)
		r.Equal(header.Size, parsedHeader.Size)
	})

	t.Run("Returns an error when given a malformed byte stream", func(t *testing.T) {
		// This test may fail if newTestSD() doesn't return valid data
		// Creating a simpler test case
		header := winacl.ACEHeader{
			Type:  winacl.AceTypeAccessAllowed,
			Flags: winacl.ACEHeaderFlagsObjectInheritAce,
			Size:  20,
		}
		buf := bytes.Buffer{}
		err := binary.Write(&buf, binary.LittleEndian, &header)
		r.NoError(err)

		// Read one byte to make the buffer incomplete
		buf.Next(1)

		_, err = winacl.NewACEHeader(&buf)
		r.Error(err)
	})
}
