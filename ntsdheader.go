package winacl

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// NtSecurityDescriptorHeader is the Header of a Security Descriptor
type NtSecurityDescriptorHeader struct {
	Revision    byte
	Sbz1        byte
	Control     uint16
	OffsetOwner uint32
	OffsetGroup uint32
	OffsetSacl  uint32
	OffsetDacl  uint32
}

const (
	DACLAutoInheritReq = 0x0100
	DACLAutoInherited  = 0x0400
	SACLAutoInherited  = 0x0800
	DACLProtected      = 0x1000
)

// NewNTSDHeader is a constructor that will parse out an
// NtSecurityDescriptorHeader from a byte buffer
func NewNTSDHeader(buf *bytes.Buffer) (header NtSecurityDescriptorHeader, err error) {
	// Use a single binary.Read call for the entire struct
	err = binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return header, fmt.Errorf("reading NTSD header: %w", err)
	}
	return header, nil
}
