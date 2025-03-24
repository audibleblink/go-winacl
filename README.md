# Go-WinACL

Go-WinACL is a Go library for working with Windows Access Control Lists (ACLs), Security Descriptors, Security Identifiers (SIDs), and related security primitives. It allows you to parse, manipulate, and create Windows security structures without requiring Windows.

## Features

- **NT Security Descriptor Parsing**: Parse binary Security Descriptors from Windows files and objects
- **SID Manipulation**: Create, parse, and validate Windows Security Identifiers (SIDs)
- **SDDL Conversion**: Convert between binary Security Descriptors and Security Descriptor Definition Language (SDDL)
- **ACE Management**: Manage Access Control Entries (ACEs) for both DACLs and SACLs
- **Windows Security Simulation**: Simulate how Windows would make access control decisions
- **Integrity Levels**: Support for Windows integrity levels (Low, Medium, High, System)
- **Capability SIDs**: Support for Windows 8+ app container capability SIDs
- **ACE Inheritance**: Model Windows ACE inheritance rules for container and object inheritance
- **Fluent SDDL Building**: Create SDDL strings using a fluent builder API

## Usage Examples

### Parsing and Converting ACLs

```go
package main

import (
	"fmt"
	"os"
	"github.com/audibleblink/go-winacl"
)

func main() {
	// Parse a binary NT Security Descriptor
	rawNTSD, _ := os.ReadFile("testdata.bin")
	ntsd, _ := winacl.NewNtSecurityDescriptor(rawNTSD)
	
	// Convert to SDDL string
	sddl := ntsd.ToSDDL()
	fmt.Println(sddl)
}
```

### Building SDDL Strings

```go
package main

import (
	"fmt"
	"github.com/audibleblink/go-winacl"
)

func main() {
	// Create an SDDL string using the fluent builder API
	builder := winacl.NewSDDLBuilder()
	
	sddl := builder.
		WithOwner("S-1-5-18").  // Local System
		WithGroup("S-1-5-32-544").  // BUILTIN\Administrators
		WithFlag("P").  // DACL Protected
		WithDACL().
		AccessAllowedACE("S-1-1-0", winacl.AccessMaskGenericRead, 0).  // Everyone: Read
		AccessDeniedACE("S-1-5-7", winacl.AccessMaskGenericWrite, 0).  // Anonymous: Deny Write
		Build()
	
	fmt.Println(sddl)
	// Output: O:S-1-5-18G:S-1-5-32-544D:P(A;;GR;;;S-1-1-0)(D;;GW;;;S-1-5-7)
}
```

### Simulating Windows Access Decisions

```go
package main

import (
	"fmt"
	"github.com/audibleblink/go-winacl"
)

func main() {
	// Create a security descriptor with an allow ACE for everyone
	everyoneSID, _ := winacl.NewSIDFromString("S-1-1-0")  // Everyone
	allowAce := winacl.NewAccessAllowedACE(everyoneSID, winacl.AccessMaskGenericRead)
	
	sd := &winacl.NtSecurityDescriptor{
		Owner: everyoneSID,
		Group: everyoneSID,
		DACL: winacl.ACL{
			Aces: []winacl.ACE{allowAce},
		},
	}

	// Create a token for a user
	userSID, _ := winacl.NewSIDFromString("S-1-5-21-1234567890-1234567890-1234567890-1001")
	token := winacl.NewTokenUser(userSID, []winacl.SID{everyoneSID})

	// Simulate a Windows access check
	result := winacl.AccessCheck(sd, token, winacl.AccessMaskGenericRead, nil)

	if result.Granted {
		fmt.Println("Access granted:", result.Reason)
	} else {
		fmt.Println("Access denied:", result.Reason)
	}
}
```

### Working with Integrity Levels

```go
package main

import (
	"fmt"
	"github.com/audibleblink/go-winacl"
)

func main() {
	// Check if a low integrity subject can write to a high integrity object
	options := &winacl.AccessCheckOptions{
		CheckIntegrity:   true,
		IntegrityPolicy:  winacl.PolicyNoWriteUp,
		SubjectIntegrity: winacl.IntegrityLevelLow,
		ObjectIntegrity:  winacl.IntegrityLevelHigh,
	}

	// Checking GenericWrite against the integrity policy
	allowed := options.SubjectIntegrity.CheckAccess(
		options.ObjectIntegrity,
		options.IntegrityPolicy,
		winacl.AccessMaskGenericWrite)

	fmt.Printf("Low integrity write to high integrity: %v\n", allowed)
	// Output: Low integrity write to high integrity: false
}
```

## Installation

```bash
go get github.com/audibleblink/go-winacl
```

## Credits

This repo was forked from https://github.com/rvazarkar/go-winacl, who did the initial work of implementing the models and parsers. It has been significantly enhanced with additional Windows security features.
