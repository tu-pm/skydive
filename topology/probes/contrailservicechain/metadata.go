package contrailservicechain

import (
	"fmt"
	"strings"

	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/topology/probes/contrailservicechain/types"
)

func commonMetadata(c types.CommonAttribute) graph.Metadata {
	m := graph.Metadata{
		"UUID":   c.UUID,
		"Name":   c.Name,
		"FqName": strings.Join(c.FqName, ":"),
	}
	if len(c.RBAC.ShareTo) == 0 {
		c.RBAC.ShareTo = nil
	}
	m.SetFieldAndNormalize("RBAC", c.RBAC)
	return m
}

func domainMetadata(d types.Domain) graph.Metadata {
	m := commonMetadata(d.CommonAttribute)
	m.SetField("Type", "TF-Domain")
	m.SetField("Manager", "TungstenFabric")
	return m
}

func networkPolicyMetadata(np types.NetworkPolicy) graph.Metadata {
	m := commonMetadata(np.CommonAttribute)
	m.SetField("Type", "TF-NetworkPolicy")
	m.SetField("Manager", "TungstenFabric")
	return m
}

func networkPolicyRuleMetadata(npr types.NetworkPolicyRule) graph.Metadata {
	m := graph.Metadata{}
	m.SetField("UUID", npr.UUID)
	m.SetField("Direction", npr.Direction)
	m.SetField("Protocol", npr.Protocol)
	return m
}

func getPortRange(p types.PortType) string {
	var start, end int
	if p.StartPort == -1 {
		start = 0
	}
	if p.EndPort == -1 {
		end = 65535
	}
	return fmt.Sprintf("%d:%d", start, end)
}

func portTupleMetadata(pt types.PortTuple) graph.Metadata {
	m := commonMetadata(pt.CommonAttribute)
	m.SetField("Type", "TF-PortTuple")
	m.SetField("Manager", "TungstenFabric")
	return m
}

func projectMetadata(p types.Project) graph.Metadata {
	m := commonMetadata(p.CommonAttribute)
	prop := graph.Metadata{}
	prop.SetFieldAndNormalize("Quota", p.Quota)
	m.SetFieldAndNormalize("Properties", map[string]interface{}(prop))
	m.SetField("Type", "TF-Project")
	m.SetField("Manager", "TungstenFabric")
	return m
}

func serviceInstanceMetadata(si types.ServiceInstance, st types.ServiceTemplate) graph.Metadata {
	m := commonMetadata(si.CommonAttribute)
	m.SetFieldAndNormalize("Properties", si.ServiceInstanceProperty)
	m.SetField("Type", "TF-ServiceInstance")
	m.SetField("Manager", "TungstenFabric")
	m.SetFieldAndNormalize("Template", st)
	return m
}

func virtualMachineMetadata(vm types.VirtualMachine) graph.Metadata {
	m := commonMetadata(vm.CommonAttribute)
	m.SetField("ServerType", vm.ServerType)
	m.SetField("Type", "TF-VirtualMachine")
	m.SetField("Manager", "TungstenFabric")
	return m
}

func virtualMachineInterfaceMetadata(vmi types.VirtualMachineInterface) graph.Metadata {
	m := commonMetadata(vmi.CommonAttribute)
	m.SetFieldAndNormalize("Properties", vmi.VirtualMachineInterfaceProperty)
	m.SetFieldAndNormalize("Properties.MacAddresses", vmi.MacAddress.MacAddresses)
	if hashFields := vmi.EcmpHashingIncludeFields; hashFields != (types.EcmpHashingIncludeFields{}) {
		m.SetFieldAndNormalize("Properties.EcmpHashingIncludeFields", hashFields)
	}
	m.SetField("Type", "TF-VirtualMachineInterface")
	m.SetField("Manager", "TungstenFabric")
	return m
}

func virtualNetworkMetadata(vn types.VirtualNetwork) graph.Metadata {
	m := commonMetadata(vn.CommonAttribute)
	m.SetFieldAndNormalize("Properties", vn.VirtualNetworkProperty)
	m.SetField("Properties.MultiServiceChainEnabled", vn.MultiServiceChainEnabled)
	m.SetField("Properties.Shareable", vn.Shareable)
	if hashFields := vn.EcmpHashingIncludeFields; hashFields != (types.EcmpHashingIncludeFields{}) {
		m.SetFieldAndNormalize("Properties.EcmpHashingIncludeFields", hashFields)
	}
	m.SetField("Type", "TF-VirtualNetwork")
	m.SetField("Manager", "TungstenFabric")
	return m
}
