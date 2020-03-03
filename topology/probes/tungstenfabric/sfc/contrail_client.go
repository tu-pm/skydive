package sfc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/skydive-project/skydive/topology/probes/tungstenfabric/sfc/types"
)

type RestApiClient struct {
	*http.Client
	baseUrl string
}

type PolicyRuleTarget struct {
	// Policy Rule Metadata
	Rule types.NetworkPolicyRule
	// Source network UUIDs
	SourceVnIDs []string
	// Destination network UUIDs
	DestinationVnIDs []string
	// ServiceInstance UUIDs
	ServiceInstanceIDs []string
}

func (client RestApiClient) FqNameToUUID(fqName, rType string) (string, error) {
	data := struct {
		FqName []string `json:"fq_name"`
		Type   string   `json:"type"`
	}{}
	res := struct {
		UUID string `json:"uuid"`
	}{}
	data.FqName = strings.Split(fqName, ":")
	data.Type = rType
	err := client.httpRequest("POST", "fqname-to-id", data, &res)
	if err != nil {
		msg := fmt.Sprintf("Failed to get UUID for fq name %s of type %s", fqName, rType)
		err = errors.Wrap(err, msg)
		return "", err
	}
	return res.UUID, nil
}

func (client RestApiClient) httpRequest(reqType, relPath string, data, res interface{}) (err error) {
	href := strings.TrimRight(client.baseUrl, "/") + "/" + relPath
	body := bytes.NewReader([]byte{})
	if data != nil {
		payloadBytes, err := json.Marshal(data)
		if err != nil {
			err = errors.Wrap(err, "Failed to marshal request payload")
			return err
		}
		body = bytes.NewReader(payloadBytes)
	}
	req, err := http.NewRequest(reqType, href, body)
	if err != nil {
		err = errors.Wrap(err, "Failed to contruct new request instance")
		return
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	response, err := client.Do(req)
	if err != nil {
		err = errors.Wrap(err, "Failed to send GET request")
		return
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		err = errors.Wrap(err, "Failed to read response body")
		return
	}
	err = json.Unmarshal(responseData, res)
	if err != nil {
		msg := fmt.Sprintf(`Failed to unmarshal json string "%s" into variable of type "%s"`, responseData, fmt.Sprintf("%T", res))
		return errors.Wrap(err, msg)
	}
	return
}

func (client RestApiClient) GetDomain(uuid string) (types.Domain, error) {
	domain := &struct {
		Domain types.Domain `json:"domain"`
	}{}
	err := client.httpRequest("GET", "domain/"+uuid, nil, domain)
	if err != nil {
		return types.Domain{}, err
	}
	return domain.Domain, err
}

func (client RestApiClient) ListDomainIDs() (uuids []string, err error) {
	domains := &struct {
		References []types.Reference `json:"domains"`
	}{}
	err = client.httpRequest("GET", "domains", nil, domains)
	if err != nil {
		return
	}
	for _, ref := range domains.References {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (client RestApiClient) ListDomains() (domains []types.Domain, err error) {
	uuids, err := client.ListDomainIDs()
	if err != nil {
		return
	}
	for _, uuid := range uuids {
		domain, err := client.GetDomain(uuid)
		if err != nil {
			return []types.Domain{}, err
		}
		domains = append(domains, domain)
	}
	return
}

func (client RestApiClient) GetNetworkPolicy(uuid string) (types.NetworkPolicy, error) {
	networkPolicy := &struct {
		NetworkPolicy types.NetworkPolicy `json:"network-policy"`
	}{}
	err := client.httpRequest("GET", "network-policy/"+uuid, nil, networkPolicy)
	if err != nil {
		return types.NetworkPolicy{}, err
	}
	return networkPolicy.NetworkPolicy, err
}

func (client RestApiClient) ListNetworkPolicyIDs() (uuids []string, err error) {
	networkPolicys := &struct {
		References []types.Reference `json:"network-policys"`
	}{}
	err = client.httpRequest("GET", "network-policys", nil, networkPolicys)
	if err != nil {
		return
	}
	for _, ref := range networkPolicys.References {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (client RestApiClient) ListNetworkPolicys() (networkPolicys []types.NetworkPolicy, err error) {
	uuids, err := client.ListNetworkPolicyIDs()
	if err != nil {
		return
	}
	for _, uuid := range uuids {
		networkPolicy, err := client.GetNetworkPolicy(uuid)
		if err != nil {
			return []types.NetworkPolicy{}, err
		}
		networkPolicys = append(networkPolicys, networkPolicy)
	}
	return
}

func (client RestApiClient) GetPortTuple(uuid string) (types.PortTuple, error) {
	portTuple := &struct {
		PortTuple types.PortTuple `json:"port-tuple"`
	}{}
	err := client.httpRequest("GET", "port-tuple/"+uuid, nil, portTuple)
	if err != nil {
		return types.PortTuple{}, err
	}
	return portTuple.PortTuple, err
}

func (client RestApiClient) ListPortTupleIDs() (uuids []string, err error) {
	portTuples := &struct {
		References []types.Reference `json:"port-tuples"`
	}{}
	err = client.httpRequest("GET", "port-tuples", nil, portTuples)
	if err != nil {
		return
	}
	for _, ref := range portTuples.References {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (client RestApiClient) ListPortTuples() (portTuples []types.PortTuple, err error) {
	uuids, err := client.ListPortTupleIDs()
	if err != nil {
		return
	}
	for _, uuid := range uuids {
		portTuple, err := client.GetPortTuple(uuid)
		if err != nil {
			return []types.PortTuple{}, err
		}
		portTuples = append(portTuples, portTuple)
	}
	return
}

func (client RestApiClient) GetProject(uuid string) (types.Project, error) {
	project := &struct {
		Project types.Project `json:"project"`
	}{}
	err := client.httpRequest("GET", "project/"+uuid, nil, project)
	if err != nil {
		return types.Project{}, err
	}
	return project.Project, err
}

func (client RestApiClient) ListProjectIDs() (uuids []string, err error) {
	projects := &struct {
		References []types.Reference `json:"projects"`
	}{}
	err = client.httpRequest("GET", "projects", nil, projects)
	if err != nil {
		return
	}
	for _, ref := range projects.References {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (client RestApiClient) ListProjects() (projects []types.Project, err error) {
	uuids, err := client.ListProjectIDs()
	if err != nil {
		return
	}
	for _, uuid := range uuids {
		project, err := client.GetProject(uuid)
		if err != nil {
			return []types.Project{}, err
		}
		projects = append(projects, project)
	}
	return
}

func (client RestApiClient) GetServiceInstance(uuid string) (types.ServiceInstance, error) {
	serviceInstance := &struct {
		ServiceInstance types.ServiceInstance `json:"service-instance"`
	}{}
	err := client.httpRequest("GET", "service-instance/"+uuid, nil, serviceInstance)
	if err != nil {
		return types.ServiceInstance{}, err
	}
	return serviceInstance.ServiceInstance, err
}

func (client RestApiClient) ListServiceInstanceIDs() (uuids []string, err error) {
	serviceInstances := &struct {
		References []types.Reference `json:"service-instances"`
	}{}
	err = client.httpRequest("GET", "service-instances", nil, serviceInstances)
	if err != nil {
		return
	}
	for _, ref := range serviceInstances.References {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (client RestApiClient) ListServiceInstances() (serviceInstances []types.ServiceInstance, err error) {
	uuids, err := client.ListServiceInstanceIDs()
	if err != nil {
		return
	}
	for _, uuid := range uuids {
		serviceInstance, err := client.GetServiceInstance(uuid)
		if err != nil {
			return []types.ServiceInstance{}, err
		}
		serviceInstances = append(serviceInstances, serviceInstance)
	}
	return
}

func (client RestApiClient) GetServiceTemplate(uuid string) (types.ServiceTemplate, error) {
	serviceTemplate := &struct {
		ServiceTemplate types.ServiceTemplate `json:"service-template"`
	}{}
	err := client.httpRequest("GET", "service-template/"+uuid, nil, serviceTemplate)
	if err != nil {
		return types.ServiceTemplate{}, err
	}
	return serviceTemplate.ServiceTemplate, err
}

func (client RestApiClient) ListServiceTemplateIDs() (uuids []string, err error) {
	serviceTemplates := &struct {
		References []types.Reference `json:"service-templates"`
	}{}
	err = client.httpRequest("GET", "service-templates", nil, serviceTemplates)
	if err != nil {
		return
	}
	for _, ref := range serviceTemplates.References {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (client RestApiClient) ListServiceTemplates() (serviceTemplates []types.ServiceTemplate, err error) {
	uuids, err := client.ListServiceTemplateIDs()
	if err != nil {
		return
	}
	for _, uuid := range uuids {
		serviceTemplate, err := client.GetServiceTemplate(uuid)
		if err != nil {
			return []types.ServiceTemplate{}, err
		}
		serviceTemplates = append(serviceTemplates, serviceTemplate)
	}
	return
}

func (client RestApiClient) GetVirtualMachine(uuid string) (types.VirtualMachine, error) {
	virtualMachine := &struct {
		VirtualMachine types.VirtualMachine `json:"virtual-machine"`
	}{}
	err := client.httpRequest("GET", "virtual-machine/"+uuid, nil, virtualMachine)
	if err != nil {
		return types.VirtualMachine{}, err
	}
	return virtualMachine.VirtualMachine, err
}

func (client RestApiClient) ListVirtualMachineIDs() (uuids []string, err error) {
	virtualMachines := &struct {
		References []types.Reference `json:"virtual-machines"`
	}{}
	err = client.httpRequest("GET", "virtual-machines", nil, virtualMachines)
	if err != nil {
		return
	}
	for _, ref := range virtualMachines.References {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (client RestApiClient) ListVirtualMachines() (virtualMachines []types.VirtualMachine, err error) {
	uuids, err := client.ListVirtualMachineIDs()
	if err != nil {
		return
	}
	for _, uuid := range uuids {
		virtualMachine, err := client.GetVirtualMachine(uuid)
		if err != nil {
			return []types.VirtualMachine{}, err
		}
		virtualMachines = append(virtualMachines, virtualMachine)
	}
	return
}

func (client RestApiClient) GetVirtualMachineInterface(uuid string) (types.VirtualMachineInterface, error) {
	virtualMachineInterface := &struct {
		VirtualMachineInterface types.VirtualMachineInterface `json:"virtual-machine-interface"`
	}{}
	err := client.httpRequest("GET", "virtual-machine-interface/"+uuid, nil, virtualMachineInterface)
	if err != nil {
		return types.VirtualMachineInterface{}, err
	}
	return virtualMachineInterface.VirtualMachineInterface, err
}

func (client RestApiClient) ListVirtualMachineInterfaceIDs() (uuids []string, err error) {
	virtualMachineInterfaces := &struct {
		References []types.Reference `json:"virtual-machine-interfaces"`
	}{}
	err = client.httpRequest("GET", "virtual-machine-interfaces", nil, virtualMachineInterfaces)
	if err != nil {
		return
	}
	for _, ref := range virtualMachineInterfaces.References {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (client RestApiClient) ListVirtualMachineInterfaces() (virtualMachineInterfaces []types.VirtualMachineInterface, err error) {
	uuids, err := client.ListVirtualMachineInterfaceIDs()
	if err != nil {
		return
	}
	for _, uuid := range uuids {
		virtualMachineInterface, err := client.GetVirtualMachineInterface(uuid)
		if err != nil {
			return []types.VirtualMachineInterface{}, err
		}
		virtualMachineInterfaces = append(virtualMachineInterfaces, virtualMachineInterface)
	}
	return
}

func (client RestApiClient) GetVirtualNetwork(uuid string) (types.VirtualNetwork, error) {
	virtualNetwork := &struct {
		VirtualNetwork types.VirtualNetwork `json:"virtual-network"`
	}{}
	err := client.httpRequest("GET", "virtual-network/"+uuid, nil, virtualNetwork)
	if err != nil {
		return types.VirtualNetwork{}, err
	}
	return virtualNetwork.VirtualNetwork, err
}

func (client RestApiClient) ListVirtualNetworkIDs() (uuids []string, err error) {
	virtualNetworks := &struct {
		References []types.Reference `json:"virtual-networks"`
	}{}
	err = client.httpRequest("GET", "virtual-networks", nil, virtualNetworks)
	if err != nil {
		return
	}
	for _, ref := range virtualNetworks.References {
		uuids = append(uuids, ref.UUID)
	}
	return
}

func (client RestApiClient) ListVirtualNetworks() (virtualNetworks []types.VirtualNetwork, err error) {
	uuids, err := client.ListVirtualNetworkIDs()
	if err != nil {
		return
	}
	for _, uuid := range uuids {
		virtualNetwork, err := client.GetVirtualNetwork(uuid)
		if err != nil {
			return []types.VirtualNetwork{}, err
		}
		virtualNetworks = append(virtualNetworks, virtualNetwork)
	}
	return
}

func (client RestApiClient) ExtractRuleTargets(p types.NetworkPolicy) (ruleTargets []PolicyRuleTarget, err error) {
	for _, rule := range p.ListRules() {
		rt := PolicyRuleTarget{
			Rule: rule,
		}

		// Get applied service instance UUIDs
		for _, fqName := range rule.ActionList.ApplyService {
			siID, err := client.FqNameToUUID(fqName, "service-instance")
			if err != nil {
				return []PolicyRuleTarget{}, err
			}
			rt.ServiceInstanceIDs = append(rt.ServiceInstanceIDs, siID)
		}

		// Get source virtual network UUIDs
		for _, srcAddress := range rule.SrcAddresses {
			// Case #1: Source address is defined by virtual network FqName
			if vnFqName := srcAddress.VirtualNetwork; len(vnFqName) > 0 {
				vnID, err := client.FqNameToUUID(vnFqName, "virtual-network")
				if err != nil {
					return []PolicyRuleTarget{}, err
				}
				rt.SourceVnIDs = append(rt.SourceVnIDs, vnID)
			}
			// Case #2: Source address is defined by a list of CIDR addresses
			if subnets := srcAddress.SubnetList; len(subnets) > 0 {
				vnIDs, err := client.cidrNetworks(subnets)
				if err != nil {
					return []PolicyRuleTarget{}, err
				}
				rt.SourceVnIDs = append(rt.SourceVnIDs, vnIDs...)
			}
			// Case #3: Source addresses from another network policy
			if policyFqName := srcAddress.NetworkPolicy; len(policyFqName) > 0 {
				vnIDs, err := client.policyNetworks(policyFqName)
				if err != nil {
					return []PolicyRuleTarget{}, err
				}
				rt.SourceVnIDs = append(rt.SourceVnIDs, vnIDs...)
			}
			// Case #4: Source addresses from a security group
			if sgFqName := srcAddress.SecurityGroup; len(sgFqName) > 0 {
				vnIDs, err := client.sgNetworks(sgFqName)
				if err != nil {
					return []PolicyRuleTarget{}, err
				}
				rt.SourceVnIDs = append(rt.SourceVnIDs, vnIDs...)
			}
		}

		// Get destination virtual network UUIDs
		for _, dstAddress := range rule.DstAddresses {
			// Case #1: Destination address is defined by virtual network FqName
			if vnFqName := dstAddress.VirtualNetwork; len(vnFqName) > 0 {
				vnID, err := client.FqNameToUUID(vnFqName, "virtual-network")
				if err != nil {
					return []PolicyRuleTarget{}, err
				}
				rt.DestinationVnIDs = append(rt.DestinationVnIDs, vnID)
			}
			// Case #2: Destination address is defined by a list of CIDR addresses
			if subnets := dstAddress.SubnetList; len(subnets) > 0 {
				vnIDs, err := client.cidrNetworks(subnets)
				if err != nil {
					return []PolicyRuleTarget{}, err
				}
				rt.DestinationVnIDs = append(rt.DestinationVnIDs, vnIDs...)
			}
			// Case #3: Destination addresses from another network policy
			if policyFqName := dstAddress.NetworkPolicy; len(policyFqName) > 0 {
				vnIDs, err := client.policyNetworks(policyFqName)
				if err != nil {
					return []PolicyRuleTarget{}, err
				}
				rt.DestinationVnIDs = append(rt.DestinationVnIDs, vnIDs...)
			}
			// Case #4: Destination addresses from a security group
			if sgFqName := dstAddress.SecurityGroup; len(sgFqName) > 0 {
				vnIDs, err := client.sgNetworks(sgFqName)
				if err != nil {
					return []PolicyRuleTarget{}, err
				}
				rt.DestinationVnIDs = append(rt.DestinationVnIDs, vnIDs...)
			}
		}
		ruleTargets = append(ruleTargets, rt)
	}
	return
}

func (client RestApiClient) sgNetworks(sgFqName string) (vnIDs []string, err error) {
	// TODO: List all virtual networks from a given security group
	return
}

func (client RestApiClient) policyNetworks(policyFqName string) (vnIDs []string, err error) {
	// TODO: List all virtual networks from a given policy
	return
}

func (client RestApiClient) cidrNetworks(subnets []types.SubnetType) (vnIDs []string, err error) {
	// TODO: List virtual networks correspond to given subnets
	return
}

// func main() {
// 	c := RestApiClient{&http.Client{}, "http://10.60.17.231:8082"}
// 	resource, err := c.GetProject("8624b505-46ff-4904-9043-5c717657f720")
// 	// resource, err := c.GetServiceTemplate("bb186e35-b026-4741-ae4a-871fda04ddd1")
// 	// resource, err := c.GetServiceInstance("b679ff98-e91d-40ce-9bb3-76276d0d6914")
// 	// resource, err := c.GetNetworkPolicy("b77affd2-1043-479e-bae4-5ed6cfba877a")
// 	// resource, err := c.GetVirtualNetwork("23684683-8358-4cc9-aa16-033d8b69086f")
// 	// resource, err := c.GetVirtualMachineInterface("2f60ebd2-49c4-40aa-ac0f-c0f6c6ae475d")
// 	if err != nil {
// 		fmt.Println(err)
// 	} else {
// 		// res := resource.ListRules()[0]
// 		m := resource.ToGraphMetadata()
// 		x, _ := json.MarshalIndent(m, "", " ")
// 		fmt.Println(string(x))
// 	}
// 	// uuid, err := c.FqNameToUUID("default-domain:admin:sfc_left", "virtual-network")
// 	// fmt.Println(uuid, err)
// }
