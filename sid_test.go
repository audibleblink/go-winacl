package winacl_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/audibleblink/go-winacl"
	"github.com/stretchr/testify/require"
)

func TestNewSID(t *testing.T) {
	r := require.New(t)

	t.Run("Creates a SID from a valid buffer", func(t *testing.T) {
		// Create a buffer with a valid SID
		buf := &bytes.Buffer{}
		
		// Revision (byte)
		buf.WriteByte(1)
		
		// NumAuthorities (byte)
		buf.WriteByte(1)
		
		// Authority (6 bytes)
		authority := []byte{0, 0, 0, 0, 0, 5} // NT Authority
		buf.Write(authority)
		
		// SubAuthority (4 bytes per NumAuthorities)
		subAuth := uint32(18) // Local System
		binary.Write(buf, binary.LittleEndian, subAuth)
		
		// Create SID
		sid, err := winacl.NewSID(buf, buf.Len())
		r.NoError(err)
		r.Equal("S-1-5-18", sid.String())
	})

	t.Run("Returns an error for too small buffer", func(t *testing.T) {
		buf := &bytes.Buffer{}
		_, err := winacl.NewSID(buf, 4)
		r.IsType(winacl.SIDInvalidError{}, err)
	})

	t.Run("Returns an error when given a malformed byte stream", func(t *testing.T) {
		buf := &bytes.Buffer{}
		fmt.Fprint(buf, "boom")
		_, err := winacl.NewSID(buf, 4)
		r.IsType(winacl.SIDInvalidError{}, err)
	})
	
	t.Run("Returns an error for invalid revision", func(t *testing.T) {
		buf := &bytes.Buffer{}
		
		// Invalid revision
		buf.WriteByte(2)
		
		// NumAuthorities
		buf.WriteByte(1)
		
		// Authority
		authority := []byte{0, 0, 0, 0, 0, 5}
		buf.Write(authority)
		
		// SubAuthority
		subAuth := uint32(18)
		binary.Write(buf, binary.LittleEndian, subAuth)
		
		_, err := winacl.NewSID(buf, buf.Len())
		r.IsType(winacl.SIDInvalidError{}, err)
	})
	
	t.Run("Returns an error for too many subauthorities", func(t *testing.T) {
		buf := &bytes.Buffer{}
		
		// Revision
		buf.WriteByte(1)
		
		// Too many NumAuthorities
		buf.WriteByte(20) // > 15 is invalid
		
		// Authority
		authority := []byte{0, 0, 0, 0, 0, 5}
		buf.Write(authority)
		
		// Not writing subauthorities since we'll fail on the check
		
		_, err := winacl.NewSID(buf, buf.Len())
		r.IsType(winacl.SIDInvalidError{}, err)
	})
}

func TestSIDString(t *testing.T) {
	r := require.New(t)

	t.Run("Returns properly formatted SID string", func(t *testing.T) {
		// Create a SID manually
		sid := winacl.SID{
			Revision:       1,
			NumAuthorities: 1,
			Authority:      []byte{0, 0, 0, 0, 0, 5},
			SubAuthorities: []uint32{18},
		}
		
		r.Equal("S-1-5-18", sid.String())
	})
	
	t.Run("Returns empty string for invalid authority length", func(t *testing.T) {
		// Create a SID with invalid authority length
		sid := winacl.SID{
			Revision:       1,
			NumAuthorities: 1,
			Authority:      []byte{0, 0, 0}, // Too short
			SubAuthorities: []uint32{18},
		}
		
		r.Equal("", sid.String())
	})
}

func TestSIDResolve(t *testing.T) {
	r := require.New(t)

	t.Run("Resolves known SID to name", func(t *testing.T) {
		// Create a SID for Local System (S-1-5-18)
		sid := winacl.SID{
			Revision:       1,
			NumAuthorities: 1,
			Authority:      []byte{0, 0, 0, 0, 0, 5},
			SubAuthorities: []uint32{18},
		}
		
		r.Equal("Local System", sid.Resolve())
	})
	
	t.Run("Resolves SID using regex pattern", func(t *testing.T) {
		// Create a SID for a domain admin (S-1-5-21-x-y-z-500)
		sid := winacl.SID{
			Revision:       1,
			NumAuthorities: 5,
			Authority:      []byte{0, 0, 0, 0, 0, 5},
			SubAuthorities: []uint32{21, 1000, 2000, 3000, 500},
		}
		
		r.Equal("Administrator", sid.Resolve())
	})
	
	t.Run("Returns SID string for unknown SID", func(t *testing.T) {
		// Create a SID with values that won't match anything
		sid := winacl.SID{
			Revision:       1,
			NumAuthorities: 2,
			Authority:      []byte{0, 0, 0, 0, 0, 9}, // Using 9 instead of typical values
			SubAuthorities: []uint32{999, 999},
		}
		
		sidString := sid.String()
		r.Equal(sidString, sid.Resolve())
	})
}
