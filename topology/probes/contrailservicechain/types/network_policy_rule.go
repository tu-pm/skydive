package types

type NetworkPolicyRule struct {
	UUID         string         `json:"rule_uuid,omitempty" structs:",omitempty"`
	Direction    string         `json:"direction"`
	Protocol     string         `json:"protocol"`
	SrcAddresses []AddressType  `json:"src_addresses"`
	SrcPorts     []PortType     `json:"src_ports"`
	Application  []string       `json:"application,omitempty" structs:",omitempty"`
	DstAddresses []AddressType  `json:"dst_addresses"`
	DstPorts     []PortType     `json:"dst_ports"`
	ActionList   ActionListType `json:"action_list"`
	Ethertype    string         `json:"ethertype"`
	Created      string         `json:"created,omitempty" structs:",omitempty"`
	LastModified string         `json:"last_modified,omitempty" structs:",omitempty"`
}

type PortType struct {
	StartPort int `json:"start_port"`
	EndPort   int `json:"end_port"`
}

type AddressType struct {
	VirtualNetwork string       `json:"virtual_network"`
	SecurityGroup  string       `json:"security_group"`
	NetworkPolicy  string       `json:"network_policy"`
	SubnetList     []SubnetType `json:"subnet_list,omitempty" structs:",omitempty"`
}

type ActionListType struct {
	SimpleAction          string           `json:"simple_action"`
	GatewayName           string           `json:"gateway_name,omitempty" structs:",omitempty"`
	ApplyService          []string         `json:"apply_service,omitempty" structs:",omitempty"`
	MirrorTo              MirrorActionType `json:"mirror_to,omitempty" structs:",omitempty"`
	AssignRoutingInstance string           `json:"assign_routing_instance,omitempty" structs:",omitempty"`
	Log                   bool             `json:"log,omitempty" structs:",omitempty"`
	Alert                 bool             `json:"alert,omitempty" structs:",omitempty"`
	QosAction             string           `json:"qos_action,omitempty" structs:",omitempty"`
	HostBasedService      bool             `json:"host_based_service,omitempty" structs:",omitempty"`
}

type SubnetType struct {
	IpPrefix    string `json:"ip_prefix,omitempty" structs:",omitempty"`
	IpPrefixLen int    `json:"ip_prefix_len,omitempty" structs:",omitempty"`
}

type MirrorActionType struct {
	AnalyzerName             string             `json:"analyzer_name,omitempty" structs:",omitempty"`
	Encapsulation            string             `json:"encapsulation,omitempty" structs:",omitempty"`
	AnalyzerIpAddress        string             `json:"analyzer_ip_address"`
	AnalyzerMacAddress       string             `json:"analyzer_mac_address,omitempty" structs:",omitempty"`
	RoutingInstance          string             `json:"routing_instance"`
	UdpPort                  int                `json:"udp_port,omitempty" structs:",omitempty"`
	JuniperHeader            bool               `json:"juniper_header,omitempty" structs:",omitempty"`
	NhMode                   string             `json:"nh_mode,omitempty" structs:",omitempty"`
	StaticNhHeader           StaticMirrorNhType `json:"static_nh_header,omitempty" structs:",omitempty"`
	NicAssistedMirroring     bool               `json:"nic_assisted_mirroring,omitempty" structs:",omitempty"`
	NicAssistedMirroringVlan int                `json:"nic_assisted_mirroring_vlan,omitempty" structs:",omitempty"`
}

type StaticMirrorNhType struct {
	VtepDstIpAddress  string `json:"vtep_dst_ip_address"`
	VtepDstMacAddress string `json:"vtep_dst_mac_address,omitempty" structs:",omitempty"`
	Vni               int    `json:"vni"`
}

func (npr NetworkPolicyRule) ListServiceInstances() (fqNames []string) {
	return npr.ActionList.ApplyService
}
