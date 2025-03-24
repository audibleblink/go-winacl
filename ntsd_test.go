package winacl_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/audibleblink/go-winacl"
)

func TestNewNtSecurityDescriptor(t *testing.T) {
	r := require.New(t)

	t.Run("Creates a new Security Descriptor from a byte slice", func(t *testing.T) {
		ntsdBytes, err := getTestNtsdBytes()
		r.NoError(err)

		ntsd, err := winacl.NewNtSecurityDescriptor(ntsdBytes)
		r.NoError(err)

		dacl := ntsd.DACL
		r.NotNil(dacl)
		r.Equal(int(dacl.Header.AceCount), len(dacl.Aces))
	})

	t.Run("Returns an error when given a malformed SD", func(t *testing.T) {
		ntsdBytes := make([]byte, 10)
		_, err := winacl.NewNtSecurityDescriptor(ntsdBytes)
		r.Error(err)
	})
}

func TestNtSecurityDescriptorString(t *testing.T) {
	r := require.New(t)

	t.Run("Returns formatted string representation", func(t *testing.T) {
		ntsd := newTestSD()
		
		result := ntsd.String()
		r.Contains(result, "Parsed Security Descriptor:")
		r.Contains(result, "Offsets:")
		r.Contains(result, "Owner=")
		r.Contains(result, "Group=")
		r.Contains(result, "Sacl=")
		r.Contains(result, "Dacl=")
	})
}

func TestToSDDL(t *testing.T) {
	t.Run("Converts a valid Security Descriptor to an SDDL string", func(t *testing.T) {
		r := require.New(t)
		sddl, _ := getTestNtsdSDDLTestString()
		ntsd := newTestSD()
		r.Equal(sddl, ntsd.ToSDDL())
	})
}
