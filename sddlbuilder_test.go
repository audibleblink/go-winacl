package winacl_test

import (
	"testing"

	"github.com/audibleblink/go-winacl"
	"github.com/stretchr/testify/require"
)

func TestSDDLBuilder(t *testing.T) {
	r := require.New(t)
	
	t.Run("Build simple SDDL with owner", func(t *testing.T) {
		builder := winacl.NewSDDLBuilder()
		
		// Add an owner (local system)
		sddl := builder.WithOwner("S-1-5-18").Build()
		
		r.Equal("O:S-1-5-18", sddl)
	})
	
	t.Run("Build SDDL with owner and group", func(t *testing.T) {
		builder := winacl.NewSDDLBuilder()
		
		// Add owner and group
		sddl := builder.
			WithOwner("S-1-5-18").
			WithGroup("S-1-5-32-544"). // BUILTIN\Administrators
			Build()
		
		r.Equal("O:S-1-5-18G:S-1-5-32-544", sddl)
	})
	
	t.Run("Build SDDL with DACL", func(t *testing.T) {
		builder := winacl.NewSDDLBuilder()
		
		// Add owner, group, and DACL with allow ACE
		sddl := builder.
			WithOwner("S-1-5-18").
			WithGroup("S-1-5-32-544").
			WithDACL().
			AccessAllowedACE("S-1-1-0", winacl.AccessMaskGenericRead, byte(winacl.ACEHeaderFlagsObjectInheritAce)).
			Build()
		
		r.Equal("O:S-1-5-18G:S-1-5-32-544D:(A;OI;GR;;;S-1-1-0)", sddl)
	})
	
	t.Run("Build SDDL with multiple ACEs", func(t *testing.T) {
		builder := winacl.NewSDDLBuilder()
		
		// Add owner, group, and DACL with multiple ACEs
		sddl := builder.
			WithOwner("S-1-5-18").
			WithGroup("S-1-5-32-544").
			WithDACL().
			AccessAllowedACE("S-1-1-0", winacl.AccessMaskGenericRead, byte(winacl.ACEHeaderFlagsObjectInheritAce)).
			AccessDeniedACE("S-1-5-7", winacl.AccessMaskGenericWrite, byte(0)). // Anonymous
			Build()
		
		r.Equal("O:S-1-5-18G:S-1-5-32-544D:(A;OI;GR;;;S-1-1-0)(D;;GW;;;S-1-5-7)", sddl)
	})
	
	t.Run("Build SDDL with flags", func(t *testing.T) {
		builder := winacl.NewSDDLBuilder()
		
		// Add DACL with protected flag (P)
		sddl := builder.
			WithOwner("S-1-5-18").
			WithFlag("P"). // Protected
			WithDACL().
			AccessAllowedACE("S-1-1-0", winacl.AccessMaskGenericRead, byte(0)).
			Build()
		
		r.Equal("O:S-1-5-18D:P(A;;GR;;;S-1-1-0)", sddl)
	})
	
	t.Run("Build SDDL with SACL for auditing", func(t *testing.T) {
		builder := winacl.NewSDDLBuilder()
		
		// Add SACL with audit ACE
		sddl := builder.
			WithOwner("S-1-5-18").
			WithSACL().
			AuditACE("S-1-1-0", winacl.AccessMaskGenericAll, byte(0), true, true). // Success and failure
			Build()
		
		r.Equal("O:S-1-5-18S:(AU;;GA;;;S-1-1-0)", sddl)
	})
	
	t.Run("Build SDDL with empty ACLs", func(t *testing.T) {
		builder := winacl.NewSDDLBuilder()
		
		// Add empty DACL and SACL
		sddl := builder.
			WithOwner("S-1-5-18").
			WithDACL().
			WithSACL().
			Build()
		
		r.Equal("O:S-1-5-18D:S:", sddl)
	})
	
	t.Run("Build SDDL with Owner SID", func(t *testing.T) {
		builder := winacl.NewSDDLBuilder()
		
		// Create a SID for Local System
		sid := winacl.SID{
			Revision:       1,
			NumAuthorities: 1,
			Authority:      []byte{0, 0, 0, 0, 0, 5}, // NT Authority
			SubAuthorities: []uint32{18},             // Local System
		}
		
		// Use the SID object directly
		sddl := builder.
			WithOwnerSID(sid).
			Build()
		
		r.Equal("O:S-1-5-18", sddl)
	})
}