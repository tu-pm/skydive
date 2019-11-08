package types

type ServiceTemplate struct {
	CommonAttribute
	ServiceTemplateProperty `json:"service_template_properties"`
	Domain                  string `json:"parent_uuid"`
}

type ServiceTemplateProperty struct {
	Version                   int                            `json:"version,omitempty" structs:",omitempty"`
	ServiceMode               string                         `json:"service_mode"`
	ServiceType               string                         `json:"service_type"`
	ImageName                 string                         `json:"image_name,omitempty" structs:",omitempty"`
	ServiceScaling            bool                           `json:"service_scaling,omitempty" structs:",omitempty"`
	InterfaceType             []ServiceTemplateInterfaceType `json:"interface_type"`
	Flavor                    string                         `json:"flavor,omitempty" structs:",omitempty"`
	ServiceVirtualizationType string                         `json:"service_virtualization_type,omitempty" structs:",omitempty"`
	AvailabilityZoneEnable    bool                           `json:"availability_zone_enable,omitempty" structs:",omitempty"`
	VrouterInstanceType       string                         `json:"vrouter_instance_type,omitempty" structs:",omitempty"`
	InstanceData              string                         `json:"instance_data,omitempty" structs:",omitempty"`
}

type ServiceTemplateInterfaceType struct {
	ServiceInterfaceType string `json:"service_interface_type"`
	SharedIp             bool   `json:"shared_ip,omitempty" structs:",omitempty"`
	StaticRouteEnable    bool   `json:"static_route_enable,omitempty" structs:",omitempty"`
}

func (st ServiceTemplate) ListDomainIDs() (uuids []string) {
	return []string{st.Domain}
}
