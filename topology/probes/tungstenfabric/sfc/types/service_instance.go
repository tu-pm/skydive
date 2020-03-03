package types

type ServiceInstance struct {
	CommonAttribute
	ServiceInstanceProperty `json:"service_instance_properties"`
	PortTupleRefs           []Reference `json:"port_tuples"`
	ServiceTemplateRefs     []Reference `json:"service_template_refs"`
	ProjectRef              string      `json:"parent_uuid"`
}

type ServiceInstanceProperty struct {
	AutoPolicy                bool                       `json:"auto_policy,omitempty" structs:",omitempty"`
	AvailabilityZone          string                     `json:"availability_zone,omitempty" structs:",omitempty"`
	InterfaceList             []ServiceInstanceInterface `json:"interface_list"`
	ServiceScaleOut           `json:"scale_out,omitempty" structs:",omitempty"`
	HAMode                    string `json:"ha_mode,omitempty" structs:",omitempty"`
	ServiceVirtualizationType string `json:"service_virtualization_type,omitempty" structs:",omitempty"`
}

type ServiceInstanceInterface struct {
	VirtualNetwork string `json:"virtual_network"`
}

type ServiceScaleOut struct {
	MaxInstances    int  `json:"max_instances"`
	EnableAutoScale bool `json:"auto_scale"`
}

func (si ServiceInstance) ListPortTupleIDs() (uuids []string) {
	for _, ref := range si.PortTupleRefs {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (si ServiceInstance) ListServiceTemplateIDs() (uuids []string) {
	for _, ref := range si.ServiceTemplateRefs {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (si ServiceInstance) ListVirtualNetworks() (uuids []string) {
	for _, prop := range si.InterfaceList {
		uuids = append(uuids, prop.VirtualNetwork)
	}
	return
}

func (si ServiceInstance) ListProjectIDs() (uuids []string) {
	return []string{si.ProjectRef}
}
