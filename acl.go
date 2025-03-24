package winacl

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ACL represents an Access Control List
type ACL struct {
	Header ACLHeader
	Aces   []ACE
}

// ACLHeader represents an Access Control List's Header
type ACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	AceCount uint16
	Sbz2     uint16
}

// NewACLHeader is a constructor that will parse out an ACLHeader from a byte buffer
func NewACLHeader(buf *bytes.Buffer) (aclh ACLHeader, err error) {
	// Use a single binary.Read call for the entire struct
	err = binary.Read(buf, binary.LittleEndian, &aclh)
	if err != nil {
		return aclh, fmt.Errorf("reading ACL header: %w", err)
	}
	return aclh, nil
}

// NewACL is a constructor that will parse out an ACL from a byte buffer
func NewACL(buf *bytes.Buffer) (acl ACL, err error) {
	acl.Header, err = NewACLHeader(buf)
	if err != nil {
		return acl, fmt.Errorf("reading ACL header: %w", err)
	}

	// Pre-allocate the slice with the exact capacity
	acl.Aces = make([]ACE, 0, acl.Header.AceCount)

	for i := 0; i < int(acl.Header.AceCount); i++ {
		ace, err := NewAce(buf)
		if err != nil {
			return acl, fmt.Errorf("reading ACE %d: %w", i, err)
		}
		acl.Aces = append(acl.Aces, ace)
	}

	return acl, nil
}

func (header *ACLHeader) ToBuffer() (bytes.Buffer, error) {
	buf := bytes.Buffer{}
	err := binary.Write(&buf, binary.LittleEndian, header)
	return buf, err
}
