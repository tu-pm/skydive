package types

type VirtualNetwork struct {
	CommonAttribute
	VirtualNetworkProperty   `json:"virtual_network_properties"`
	EcmpHashingIncludeFields `json:"ecmp_hashing_include_fields"`
	MultiServiceChainEnabled bool   `json:"multi_policy_service_chains_enabled"`
	Shareable                bool   `json:"is_shared"`
	ProjectRef               string `json:"parent_uuid"`
}

type VirtualNetworkProperty struct {
	AllowTransit           bool   `json:"allow_transit,omitempty" structs:",omitempty"`
	NetworkId              int    `json:"network_id,omitempty" structs:",omitempty"`
	VxlanNetworkIdentifier int    `json:"vxlan_network_identifier"`
	ForwardingMode         string `json:"forwarding_mode,omitempty" structs:",omitempty"`
	Rpf                    string `json:"rpf,omitempty" structs:",omitempty"`
	MirrorDestination      bool   `json:"mirror_destination,omitempty" structs:",omitempty"`
	MaxFlows               int    `json:"max_flows,omitempty" structs:",omitempty"`
}

func (vn VirtualNetwork) ListProjectIDs() (uuids []string) {
	return []string{vn.ProjectRef}
}
