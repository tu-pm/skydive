package types

type Project struct {
	CommonAttribute
	Quota              Quota       `json:"quota"`
	VirtualNetworkRefs []Reference `json:"virtual_networks"`
	DomainRef          string      `json:"parent_uuid"`
}

type Quota struct {
	Defaults                  int `json:"defaults,omitempty" structs:",omitempty"`
	FloatingIp                int `json:"floating_ip,omitempty" structs:",omitempty"`
	InstanceIp                int `json:"instance_ip,omitempty" structs:",omitempty"`
	VirtualMachineInterface   int `json:"virtual_machine_interface,omitempty" structs:",omitempty"`
	VirtualNetwork            int `json:"virtual_network,omitempty" structs:",omitempty"`
	VirtualRouter             int `json:"virtual_router,omitempty" structs:",omitempty"`
	VirtualDNS                int `json:"virtual_DNS,omitempty" structs:",omitempty"`
	VirtualDNSRecord          int `json:"virtual_DNS_record,omitempty" structs:",omitempty"`
	BgpRouter                 int `json:"bgp_router,omitempty" structs:",omitempty"`
	NetworkIpam               int `json:"network_ipam,omitempty" structs:",omitempty"`
	AccessControlList         int `json:"access_control_list,omitempty" structs:",omitempty"`
	NetworkPolicy             int `json:"network_policy,omitempty" structs:",omitempty"`
	FloatingIpPool            int `json:"floating_ip_pool,omitempty" structs:",omitempty"`
	ServiceTemplate           int `json:"service_template,omitempty" structs:",omitempty"`
	ServiceInstance           int `json:"service_instance,omitempty" structs:",omitempty"`
	LogicalRouter             int `json:"logical_router,omitempty" structs:",omitempty"`
	SecurityGroup             int `json:"security_group,omitempty" structs:",omitempty"`
	SecurityGroupRule         int `json:"security_group_rule,omitempty" structs:",omitempty"`
	Subnet                    int `json:"subnet,omitempty" structs:",omitempty"`
	GlobalVrouterConfig       int `json:"global_vrouter_config,omitempty" structs:",omitempty"`
	LoadbalancerPool          int `json:"loadbalancer_pool,omitempty" structs:",omitempty"`
	LoadbalancerMember        int `json:"loadbalancer_member,omitempty" structs:",omitempty"`
	LoadbalancerHealthmonitor int `json:"loadbalancer_healthmonitor,omitempty" structs:",omitempty"`
	VirtualIp                 int `json:"virtual_ip,omitempty" structs:",omitempty"`
	SecurityLoggingObject     int `json:"security_logging_object,omitempty" structs:",omitempty"`
	RouteTable                int `json:"route_table,omitempty" structs:",omitempty"`
	FirewallGroup             int `json:"firewall_group,omitempty" structs:",omitempty"`
	FirewallPolicy            int `json:"firewall_policy,omitempty" structs:",omitempty"`
	FirewallRule              int `json:"firewall_rule,omitempty" structs:",omitempty"`
	HostBasedService          int `json:"host_based_service,omitempty" structs:",omitempty"`
}

func (p Project) ListVirtualNetworkIDs() (uuids []string) {
	for _, ref := range p.VirtualNetworkRefs {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (p Project) ListDomainIDs() (uuids []string) {
	return []string{p.DomainRef}
}
