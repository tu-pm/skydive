package types

type Reference struct {
	UUID string `json:"uuid"`
}

type EcmpHashingIncludeFields struct {
	HashingConfigured bool `json:"hashing_configured,omitempty"`
	SourceIp          bool `json:"source_ip,omitempty"`
	DestinationIp     bool `json:"destination_ip,omitempty"`
	IpProtocol        bool `json:"ip_protocol,omitempty"`
	SourcePort        bool `json:"source_port,omitempty"`
	DestinationPort   bool `json:"destination_port,omitempty"`
}

type CommonAttribute struct {
	UUID   string   `json:"uuid"`
	Name   string   `json:"name"`
	FqName []string `json:"fq_name"`
	RBAC   Perms2   `json:"perms2"`
}

type Perms2 struct {
	OwnerTenant string      `json:"owner"`
	OwnerAccess int         `json:"owner_access"`
	OtherAccess int         `json:"other_access,omitempty" structs:",omitempty"`
	ShareTo     []ShareType `json:"share,omitempty" structs:",omitempty"`
}

type ShareType struct {
	Tenant       string `json:"tenant"`
	TenantAccess int    `json:"tenant_access"`
}
