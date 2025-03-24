package winacl_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/audibleblink/go-winacl"

	"github.com/stretchr/testify/require"
)

func TestNewAce(t *testing.T) {
	r := require.New(t)

	t.Run("Creates a basic ACE from valid buffer", func(t *testing.T) {
		// Create a buffer with a basic ACE structure
		buf := &bytes.Buffer{}
		
		// Write header
		header := winacl.ACEHeader{
			Type:  winacl.AceTypeAccessAllowed,
			Flags: winacl.ACEHeaderFlagsObjectInheritAce,
			Size:  24, // Size needs to accommodate header + access mask + SID
		}
		err := binary.Write(buf, binary.LittleEndian, &header)
		r.NoError(err)
		
		// Write access mask
		accessMask := uint32(winacl.AccessMaskGenericRead | winacl.AccessMaskReadControl)
		err = binary.Write(buf, binary.LittleEndian, accessMask)
		r.NoError(err)
		
		// Write minimal SID (simplified for testing)
		// Revision
		err = binary.Write(buf, binary.LittleEndian, byte(1))
		r.NoError(err)
		// NumAuthorities
		err = binary.Write(buf, binary.LittleEndian, byte(1))
		r.NoError(err)
		// Authority
		authority := []byte{0, 0, 0, 0, 0, 5} // NT Authority
		_, err = buf.Write(authority)
		r.NoError(err)
		// SubAuthority
		subAuth := uint32(18) // Local System
		err = binary.Write(buf, binary.LittleEndian, subAuth)
		r.NoError(err)
		
		// Parse ACE
		ace, err := winacl.NewAce(buf)
		r.NoError(err)
		r.Equal(winacl.AceTypeAccessAllowed, ace.Header.Type)
		r.Equal(winacl.ACEHeaderFlagsObjectInheritAce, ace.Header.Flags)
		r.Equal(uint32(winacl.AccessMaskGenericRead|winacl.AccessMaskReadControl), ace.AccessMask.Raw())
		r.Equal("S-1-5-18", ace.ObjectAce.GetPrincipal().String())
	})

	t.Run("Creates an advanced ACE from valid buffer", func(t *testing.T) {
		// Create a buffer with an advanced ACE structure
		buf := &bytes.Buffer{}
		
		// Write header
		header := winacl.ACEHeader{
			Type:  winacl.AceTypeAccessAllowedObject,
			Flags: winacl.ACEHeaderFlagsObjectInheritAce,
			Size:  48, // Size needs to be larger for object ACE
		}
		err := binary.Write(buf, binary.LittleEndian, &header)
		r.NoError(err)
		
		// Write access mask
		accessMask := uint32(winacl.AccessMaskGenericRead)
		err = binary.Write(buf, binary.LittleEndian, accessMask)
		r.NoError(err)
		
		// Write ACE inheritance flags
		inheritanceFlags := uint32(winacl.ACEInheritanceFlagsObjectTypePresent)
		err = binary.Write(buf, binary.LittleEndian, inheritanceFlags)
		r.NoError(err)
		
		// Write ObjectType GUID
		guid := winacl.GUID{
			Data1: 0x12345678,
			Data2: 0x1234,
			Data3: 0x5678,
			Data4: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		}
		err = binary.Write(buf, binary.LittleEndian, guid)
		r.NoError(err)
		
		// Write minimal SID (simplified for testing)
		err = binary.Write(buf, binary.LittleEndian, byte(1)) // Revision
		r.NoError(err)
		err = binary.Write(buf, binary.LittleEndian, byte(1)) // NumAuthorities
		r.NoError(err)
		authority := []byte{0, 0, 0, 0, 0, 5} // NT Authority
		_, err = buf.Write(authority)
		r.NoError(err)
		subAuth := uint32(18) // Local System
		err = binary.Write(buf, binary.LittleEndian, subAuth)
		r.NoError(err)
		
		// Parse ACE
		ace, err := winacl.NewAce(buf)
		r.NoError(err)
		r.Equal(winacl.AceTypeAccessAllowedObject, ace.Header.Type)
		advancedAce, ok := ace.ObjectAce.(winacl.AdvancedAce)
		r.True(ok, "Expected AdvancedAce type")
		r.Equal(winacl.ACEInheritanceFlagsObjectTypePresent, advancedAce.Flags)
		r.Equal("S-1-5-18", advancedAce.SecurityIdentifier.String())
	})

	t.Run("Returns error on invalid buffer", func(t *testing.T) {
		buf := &bytes.Buffer{}
		// Write incomplete data
		header := winacl.ACEHeader{
			Type: winacl.AceTypeAccessAllowed,
		}
		_ = binary.Write(buf, binary.LittleEndian, &header)
		
		// Read one byte to make the buffer incomplete
		buf.Next(1)
		
		_, err := winacl.NewAce(buf)
		r.Error(err)
	})
}

func TestNewBasicAce(t *testing.T) {
	r := require.New(t)

	t.Run("Creates basic ACE from valid buffer", func(t *testing.T) {
		buf := &bytes.Buffer{}
		
		// Write minimal SID (simplified for testing)
		err := binary.Write(buf, binary.LittleEndian, byte(1)) // Revision
		r.NoError(err)
		err = binary.Write(buf, binary.LittleEndian, byte(1)) // NumAuthorities
		r.NoError(err)
		authority := []byte{0, 0, 0, 0, 0, 5} // NT Authority
		_, err = buf.Write(authority)
		r.NoError(err)
		subAuth := uint32(18) // Local System
		err = binary.Write(buf, binary.LittleEndian, subAuth)
		r.NoError(err)
		
		// Total size is calculated as:
		// header (4) + access mask (4) + SID (8+4*NumAuthorities)
		// = 8 + (8 + 4 * 1) = 8 + 12 = 20
		basicAce, err := winacl.NewBasicAce(buf, 20)
		r.NoError(err)
		r.Equal("S-1-5-18", basicAce.SecurityIdentifier.String())
	})

	t.Run("Returns error on invalid buffer", func(t *testing.T) {
		// This test is more complex because the error happens in the NewSID function
		// which expects a certain minimum buffer size. To create a valid test case,
		// we'll create an almost complete buffer but with data that will cause NewSID to fail
		buf := &bytes.Buffer{}
		
		// Write a valid revision
		err := binary.Write(buf, binary.LittleEndian, byte(1)) // Revision
		r.NoError(err)
		
		// Write an invalid number of authorities (too large to be valid)
		err = binary.Write(buf, binary.LittleEndian, byte(20)) // NumAuthorities (invalid value > 15)
		r.NoError(err)
		
		// Write enough data to make the buffer the expected size
		authority := []byte{0, 0, 0, 0, 0, 5} // Authority
		_, err = buf.Write(authority)
		r.NoError(err)
		
		// Since the function expects more data than available due to the large NumAuthorities,
		// this should fail with an error
		_, err = winacl.NewBasicAce(buf, 20)
		r.Error(err)
	})
}

func TestNewAdvancedAce(t *testing.T) {
	r := require.New(t)

	t.Run("Creates advanced ACE from valid buffer", func(t *testing.T) {
		buf := &bytes.Buffer{}
		
		// Write inheritance flags
		flags := uint32(winacl.ACEInheritanceFlagsObjectTypePresent)
		err := binary.Write(buf, binary.LittleEndian, flags)
		r.NoError(err)
		
		// Write ObjectType GUID
		guid := winacl.GUID{
			Data1: 0x12345678,
			Data2: 0x1234,
			Data3: 0x5678,
			Data4: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		}
		err = binary.Write(buf, binary.LittleEndian, guid)
		r.NoError(err)
		
		// Write minimal SID (simplified for testing)
		err = binary.Write(buf, binary.LittleEndian, byte(1)) // Revision
		r.NoError(err)
		err = binary.Write(buf, binary.LittleEndian, byte(1)) // NumAuthorities
		r.NoError(err)
		authority := []byte{0, 0, 0, 0, 0, 5} // NT Authority
		_, err = buf.Write(authority)
		r.NoError(err)
		subAuth := uint32(18) // Local System
		err = binary.Write(buf, binary.LittleEndian, subAuth)
		r.NoError(err)
		
		// Size calculation: 
		// header (4) + access mask (4) + flags (4) + GUID (16) + SID (8+4*NumAuthorities)
		// = 8 + 4 + 16 + 12 = 40
		advancedAce, err := winacl.NewAdvancedAce(buf, 40)
		r.NoError(err)
		r.Equal(winacl.ACEInheritanceFlagsObjectTypePresent, advancedAce.Flags)
		r.Equal("S-1-5-18", advancedAce.SecurityIdentifier.String())
	})

	t.Run("Returns error on invalid buffer", func(t *testing.T) {
		buf := &bytes.Buffer{}
		
		// Write inheritance flags
		flags := uint32(winacl.ACEInheritanceFlagsObjectTypePresent)
		err := binary.Write(buf, binary.LittleEndian, flags)
		r.NoError(err)
		
		// Write incomplete GUID data (just enough to trigger an error but not panic)
		// First write Data1 (uint32)
		data1 := uint32(0x12345678)
		err = binary.Write(buf, binary.LittleEndian, data1)
		r.NoError(err)
		
		// Then a partial Data2 (uint16) to cause the error
		data2Partial := []byte{0x12}  // Only write one byte of a uint16 to cause error
		_, err = buf.Write(data2Partial)
		r.NoError(err)
		
		// This should fail during GUID parsing
		_, err = winacl.NewAdvancedAce(buf, 40)
		r.Error(err)
	})
}
