package winacl

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// NewAce creates a new ACE from a byte buffer
func NewAce(buf *bytes.Buffer) (ACE, error) {
	ace := ACE{}
	var err error

	ace.Header, err = NewACEHeader(buf)
	if err != nil {
		return ace, fmt.Errorf("reading ACE header: %w", err)
	}

	err = binary.Read(buf, binary.LittleEndian, &ace.AccessMask.Value)
	if err != nil {
		return ace, fmt.Errorf("reading ACE access mask: %w", err)
	}

	// Process ACE based on its type
	switch ace.Header.Type {
	case AceTypeAccessAllowed, AceTypeAccessDenied, AceTypeSystemAudit, AceTypeSystemAlarm, 
	     AceTypeAccessAllowedCallback, AceTypeAccessDeniedCallback, AceTypeSystemAuditCallback, AceTypeSystemAlarmCallback:
		
		ace.ObjectAce, err = NewBasicAce(buf, ace.Header.Size)
		if err != nil {
			return ace, fmt.Errorf("parsing basic ACE: %w", err)
		}

	case AceTypeAccessAllowedObject, AceTypeAccessDeniedObject, AceTypeSystemAuditObject, AceTypeSystemAlarmObject, 
	     AceTypeAccessAllowedCallbackObject, AceTypeAccessDeniedCallbackObject, AceTypeSystemAuditCallbackObject, AceTypeSystemAlarmCallbackObject:
		
		ace.ObjectAce, err = NewAdvancedAce(buf, ace.Header.Size)
		if err != nil {
			return ace, fmt.Errorf("parsing advanced ACE: %w", err)
		}

	default:
		return ace, fmt.Errorf("unknown ACE type: %d", ace.Header.Type)
	}

	return ace, nil
}

// NewACEHeader creates a new ACE header from a byte buffer
func NewACEHeader(buf *bytes.Buffer) (header ACEHeader, err error) {
	// Use a single binary.Read call for the entire struct
	err = binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return header, fmt.Errorf("reading ACE header: %w", err)
	}
	return header, nil
}

// NewBasicAce creates a new basic ACE from a byte buffer
func NewBasicAce(buf *bytes.Buffer, totalSize uint16) (BasicAce, error) {
	oa := BasicAce{}
	
	// Calculate remaining size for SID (total size minus header and access mask)
	sidSize := int(totalSize) - 8
	if sidSize <= 0 {
		return oa, fmt.Errorf("invalid ACE size for SID: %d", sidSize)
	}
	
	sid, err := NewSID(buf, sidSize)
	if err != nil {
		return oa, fmt.Errorf("parsing SID in basic ACE: %w", err)
	}
	
	oa.SecurityIdentifier = sid
	return oa, nil
}

// NewAdvancedAce creates a new advanced ACE from a byte buffer
func NewAdvancedAce(buf *bytes.Buffer, totalSize uint16) (AdvancedAce, error) {
	oa := AdvancedAce{}
	var err error
	
	// Read flags
	err = binary.Read(buf, binary.LittleEndian, &oa.Flags)
	if err != nil {
		return oa, fmt.Errorf("reading ACE inheritance flags: %w", err)
	}
	
	// Track bytes read (4 for header + 4 for access mask + 4 for flags)
	offset := 12
	
	// Read object type if present
	if (oa.Flags & ACEInheritanceFlagsObjectTypePresent) != 0 {
		oa.ObjectType, err = NewGUID(buf)
		if err != nil {
			return oa, fmt.Errorf("reading object type GUID: %w", err)
		}
		offset += 16
	}

	// Read inherited object type if present
	if (oa.Flags & ACEInheritanceFlagsInheritedObjectTypePresent) != 0 {
		oa.InheritedObjectType, err = NewGUID(buf)
		if err != nil {
			return oa, fmt.Errorf("reading inherited object type GUID: %w", err)
		}
		offset += 16
	}

	// Calculate remaining size for SID
	sidSize := int(totalSize) - offset
	if sidSize <= 0 {
		return oa, fmt.Errorf("invalid advanced ACE size for SID: %d", sidSize)
	}
	
	// Read SID
	sid, err := NewSID(buf, sidSize)
	if err != nil {
		return oa, fmt.Errorf("parsing SID in advanced ACE: %w", err)
	}
	
	oa.SecurityIdentifier = sid
	return oa, nil
}
