package winacl_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/audibleblink/go-winacl"
	"github.com/stretchr/testify/require"
)

func TestNewGUID(t *testing.T) {
	r := require.New(t)

	t.Run("Creates a GUID from a valid buffer", func(t *testing.T) {
		// Create a buffer with valid GUID data
		buf := &bytes.Buffer{}
		
		// Write a valid GUID
		data1 := uint32(0x12345678)
		data2 := uint16(0x1234)
		data3 := uint16(0x5678)
		data4 := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		
		binary.Write(buf, binary.LittleEndian, data1)
		binary.Write(buf, binary.LittleEndian, data2)
		binary.Write(buf, binary.LittleEndian, data3)
		binary.Write(buf, binary.LittleEndian, data4)
		
		guid, err := winacl.NewGUID(buf)
		r.NoError(err)
		r.Equal("12345678-1234-5678-0102-030405060708", guid.String())
	})

	t.Run("Returns an error when given a malformed byte stream", func(t *testing.T) {
		buf := &bytes.Buffer{}
		fmt.Fprint(buf, "boom")
		_, err := winacl.NewGUID(buf)
		r.Error(err)
	})
}

func TestGUIDString(t *testing.T) {
	r := require.New(t)

	t.Run("Returns formatted GUID string", func(t *testing.T) {
		guid := winacl.GUID{
			Data1: 0x12345678,
			Data2: 0x1234,
			Data3: 0x5678,
			Data4: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		}
		
		r.Equal("12345678-1234-5678-0102-030405060708", guid.String())
	})

	t.Run("Returns empty string for null GUID", func(t *testing.T) {
		guid := winacl.GUID{
			Data1: 0,
			Data2: 0,
			Data3: 0,
			Data4: [8]byte{0, 0, 0, 0, 0, 0, 0, 0},
		}
		
		r.Equal("", guid.String())
	})
}

func TestGUIDResolve(t *testing.T) {
	r := require.New(t)

	t.Run("Resolves known GUID to name", func(t *testing.T) {
		// GUID for DS-Replication-Get-Changes
		guid := winacl.GUID{
			Data1: 0x1131f6aa,
			Data2: 0x9c07,
			Data3: 0x11d1,
			Data4: [8]byte{0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2},
		}
		
		name := guid.Resolve()
		r.Equal("DS-Replication-Get-Changes", name)
	})

	t.Run("Returns GUID string for unknown GUID", func(t *testing.T) {
		// Using an unknown GUID
		guid := winacl.GUID{
			Data1: 0x99999999,
			Data2: 0x9999,
			Data3: 0x9999,
			Data4: [8]byte{0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99},
		}
		
		// Should return the GUID string itself when not known
		r.Equal("99999999-9999-9999-9999-999999999999", guid.Resolve())
	})
}
