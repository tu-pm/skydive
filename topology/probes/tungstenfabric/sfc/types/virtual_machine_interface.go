package types

type VirtualMachineInterface struct {
	CommonAttribute
	MacAddress                      `json:"virtual_machine_interface_mac_addresses"`
	VirtualMachineInterfaceProperty `json:"virtual_machine_interface_properties"`
	EcmpHashingIncludeFields        `json:"ecmp_hashing_include_fields"`
	VirtualMachineRefs              []Reference `json:"virtual_machine_refs"`
	// VirtualNetworkRefs              []Reference `json:"virtual_network_refs"`
	PortTupleRefs []Reference `json:"port_tuple_refs"`
}

type MacAddress struct {
	MacAddresses []string `json:"mac_address"`
}

type VirtualMachineInterfaceProperty struct {
	ServiceInterfaceType string `json:"service_interface_type,omitempty" structs:",omitempty"`
	LocalPreference      int    `json:"local_preference,omitempty" structs:",omitempty"`
	SubInterfaceVlanTag  int    `json:"sub_interface_vlan_tag,omitempty" structs:",omitempty"`
	MaxFlows             int    `json:"max_flows,omitempty" structs:",omitempty"`
}

func (vmi VirtualMachineInterface) ListVirtualMachineIDs() (uuids []string) {
	for _, ref := range vmi.VirtualMachineRefs {
		uuids = append(uuids, ref.UUID)
	}
	return
}

// func (vmi VirtualMachineInterface) ListVirtualNetworkIDs() (uuids []string) {
// 	for _, ref := range vmi.VirtualNetworkRefs {
// 		uuids = append(uuids, ref.UUID)
// 	}
// 	return
// }

func (vmi VirtualMachineInterface) ListPortTupleIDs() (uuids []string) {
	for _, ref := range vmi.PortTupleRefs {
		uuids = append(uuids, ref.UUID)
	}
	return
}
