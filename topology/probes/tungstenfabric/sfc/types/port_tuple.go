package types

type PortTuple struct {
	CommonAttribute
	VirtualMachineInterfaceRefs []Reference `json:"virtual_machine_interface_back_refs,omitempty"`
	ServiceInstanceRef          string      `json:"parent_uuid"`
}

func (pt PortTuple) ListServiceInstanceIDs() (uuids []string) {
	return []string{pt.ServiceInstanceRef}
}

func (pt PortTuple) ListVirtualMachineInterfaceIDs() (uuids []string) {
	for _, ref := range pt.VirtualMachineInterfaceRefs {
		uuids = append(uuids, ref.UUID)
	}
	return
}
