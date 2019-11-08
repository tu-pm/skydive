package types

type VirtualMachine struct {
	CommonAttribute
	InterfaceRefs []Reference `json:"virtual_machine_interface_back_refs"`
	ServerType    string      `json:"server_type"`
}

func (vm VirtualMachine) ListVirtualMachineInterfaceIDs() (uuids []string) {
	for _, ref := range vm.InterfaceRefs {
		uuids = append(uuids, ref.UUID)
	}
	return
}
