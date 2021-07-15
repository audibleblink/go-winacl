package winacl

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// GUID holds the various parts of a GUID
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// NewGUID is a constructor that will parse out a GUID from a byte buffer
func NewGUID(buf *bytes.Buffer) GUID {
	guid := GUID{}
	binary.Read(buf, binary.LittleEndian, &guid.Data1)
	binary.Read(buf, binary.LittleEndian, &guid.Data2)
	binary.Read(buf, binary.LittleEndian, &guid.Data3)
	binary.Read(buf, binary.LittleEndian, &guid.Data4)
	return guid
}

// String will return the human-readable version of a GUID
// It returns an empty string in case of a null-initialized
// GUID
func (g GUID) String() string {
	guid := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		g.Data1, g.Data2, g.Data3, g.Data4[0:2], g.Data4[2:8])
	if guid == "00000000-0000-0000-0000-000000000000" {
		guid = ""
	}
	return guid
}

// Resolve returns the common human-readable Object name as
// defined by Microsoft. If the GUID is not resolvable, the
// GUID string will be returned instead
//
// https://docs.microsoft.com/en-us/windows/win32/adschema/control-access-rights
func (g GUID) Resolve() string {
	guid := g.String()
	found := ControlAccessRightsGUIDs[guid]
	if found != "" {
		return found
	}
	return guid
}

var ControlAccessRightsGUIDs = map[string]string{
	//Extended Rights Guids
	"ee914b82-0a98-11d1-adbb-00c04fd8d5cd": "Abandon Replication",
	"440820ad-65b4-11d1-a3da-0000f875ae0d": "Add GUID",
	"1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate Rids",
	"68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed to Authenticate",
	"edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply Group Policy",
	"0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
	"014bf69c-7b3b-11d1-85f6-08002be74fab": "Change Domain Master",
	"cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change Infrastructure Master",
	"bae50096-4752-11d1-9052-00c04fc2d4cf": "Change PDC",
	"d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change Rid Master",
	"e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Master",
	"e2a36dc9-ae17-47c3-b58b-be34c55ba633": "Create Inbound Forest Trust",
	"fec364e0-0a98-11d1-adbb-00c04fd8d5cd": "Do Garbage Collection",
	"ab721a52-1e2f-11d0-9819-00aa0040529b": "Domain-Administer-Server",
	"69ae6200-7f46-11d2-b9ad-00c04f79f805": "Check Stale Phantoms",
	"3e0f7e18-2c7a-4c10-ba82-4d926db99a3e": "Allow a DC to create a clone of itself",
	"2f16c4a5-b98e-432c-952a-cb388ba33f2e": "Execute Forest Update Script",
	"9923a32a-3607-11d2-b9be-0000f87a36b2": "Add/Remove Replica In Domain",
	"4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "Query Self Quota",
	"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "Replicating Directory Changes",
	"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "Replicating Directory Changes All",
	"89e95b76-444d-4c62-991a-0facbeda640c": "Replicating Directory Changes In Filtered Set",
	"1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "Manage Replication Topology",
	"f98340fb-7c5b-4cdb-a00b-2ebdfa115a96": "Monitor Active Directory Replication",
	"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "Replication Synchronization",
	"05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": "Enable Per User Reversibly Encrypted Password",
	"b7b1b3de-ab09-4242-9e30-9980e5d322f7": "Generate Resultant Set of Policy (Logging)",
	"b7b1b3dd-ab09-4242-9e30-9980e5d322f7": "Generate Resultant Set of Policy (Planning)",
	"7c0e2a7c-a419-48e4-a995-10180aad54dd": "Manage Optional Features for Active Directory",
	"ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate SID History",
	"b4e60130-df3f-11d1-9c86-006008764d0e": "Open Connector Queue",
	"06bd3201-df3e-11d1-9c86-006008764d0e": "Allows peeking at messages in the queue.",
	"4b6e08c3-df3c-11d1-9c86-006008764d0e": "msmq-Peek-computer-Journal",
	"4b6e08c1-df3c-11d1-9c86-006008764d0e": "Peek Dead Letter",
	"06bd3200-df3e-11d1-9c86-006008764d0e": "Receive Message",
	"4b6e08c2-df3c-11d1-9c86-006008764d0e": "Receive Computer Journal",
	"4b6e08c0-df3c-11d1-9c86-006008764d0e": "Receive Dead Letter",
	"06bd3203-df3e-11d1-9c86-006008764d0e": "Receive Journal",
	"06bd3202-df3e-11d1-9c86-006008764d0e": "Send Message",
	"a1990816-4298-11d1-ade2-00c04fd8d5cd": "Open Address List",
	"1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "Read Only Replication Secret Synchronization",
	"45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate Tombstones",
	"0bc1554e-0a99-11d1-adbb-00c04fd8d5cd": "Recalculate Hierarchy",
	"62dd28a8-7f46-11d2-b9ad-00c04f79f805": "Recalculate Security Inheritance",
	"ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive As",
	"9432c620-033c-4db7-8b58-14ef6d0bf477": "Refresh Group Cache for Logons",
	"1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8": "Reload SSL/TLS Certificate",
	"7726b9d5-a4b4-4288-a6b2-dce952e80a7f": "Run Protect Admin Groups Task",
	"91d67418-0135-4acc-8d79-c08e857cfbec": "Enumerate Entire SAM Domain",
	"ab721a54-1e2f-11d0-9819-00aa0040529b": "Send As",
	"ab721a55-1e2f-11d0-9819-00aa0040529b": "Send To",
	"ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire Password",
	"280f369c-67c7-438e-ae98-1d46f3c6f541": "Update Password Not Required Bit",
	"be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update Schema Cache",
	"ab721a53-1e2f-11d0-9819-00aa0040529b": "Change Password",
	"00299570-246d-11d0-a768-00aa006e0529": "Reset Password",

	// Property Sets
	"72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS Host Name Attributes",
	"b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Other Domain Parameters (for use by SAM)",
	"c7407360-20bf-11d0-a768-00aa006e0529": "Domain Password & Lockout Policies",
	"e45795b2-9455-11d1-aebd-0000f80367c1": "Phone and Mail Options",
	"59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General Information",
	"bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Group Membership",
	"ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess",
	"77b5b886-944a-11d1-aebd-0000f80367c1": "Personal Information",
	"91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private Information",
	"e48d0154-bcf8-11d1-8702-00c04fb96050": "Public Information",
	"037088f8-0ae1-11d2-b422-00a0c968f939": "Remote Access Information",
	"5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal Server License Server",
	"4c164200-20c0-11d0-a768-00aa006e0529": "Account Restrictions",
	"5f202010-79a5-11d0-9020-00c04fc2d4cf": "Logon Information",
	"e45795b3-9455-11d1-aebd-0000f80367c1": "Web Information",

	// Validated Writes
	"bf9679c0-0de6-11d0-a285-00aa003049e2": "Add/Remove self as member",
	// "72e39547-7b18-11d1-adef-00c04fd8d5cd": "Validated write to DNS host name", DUPLICATE?
	"80863791-dbe9-4eb8-837e-7f0ab55d9ac7": "Validated write to MS DS Additional DNS Host Name",
	"d31a8757-2447-4545-8081-3bb610cacbf2": "Validated write to MS DS behavior version",
	"f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated write to service principal name",

	// AD
	"bf967aa5-0de6-11d0-a285-00aa003049e2": "OrganizationalUnits",
	"bf967a86-0de6-11d0-a285-00aa003049e2": "Computer",
	"bf967aba-0de6-11d0-a285-00aa003049e2": "User",
	"bf967a9c-0de6-11d0-a285-00aa003049e2": "Groups",
	"5cb41ed0-0e4c-11d0-a286-00aa003049e2": "Contacts",
	"bf967a7f-0de6-11d0-a285-00aa003049e2": "UserCertificate",
	"6db69a1c-9422-11d1-aebd-0000f80367c1": "Terminal Server",
	"46a9b11d-60ae-405a-b7e8-ff8a58d456d2": "tokenGroupsGlobalAndUniversal",
	"4828cc14-1437-45bc-9b07-ad6f015e5f28": "inetOrgPerson",
}
