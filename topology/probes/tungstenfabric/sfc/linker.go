package sfc

import (
	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/logging"
	"github.com/skydive-project/skydive/topology"
)

type domainProjectLinker struct {
	probe *Probe
}

func (l *domainProjectLinker) GetABLinks(dmNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	dmID, err := dmNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	dm, err := probe.client.GetDomain(dmID)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	for _, pjID := range dm.ListProjectIDs() {
		if pjNode, _ := probe.pjIndexer.GetNode(pjID); pjNode != nil {
			link, err := topology.NewLink(probe.graph, dmNode, pjNode, "ownership", nil)
			if err != nil {
				logging.GetLogger().Error(err)
				continue
			}
			edges = append(edges, link)
		}
	}
	return
}

func (l *domainProjectLinker) GetBALinks(pjNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	pjID, err := pjNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	pj, err := probe.client.GetProject(pjID)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	for _, dmID := range pj.ListDomainIDs() {
		if dmNode, _ := probe.dmIndexer.GetNode(dmID); dmNode != nil {
			link, err := topology.NewLink(probe.graph, dmNode, pjNode, "ownership", nil)
			if err != nil {
				logging.GetLogger().Error(err)
				continue
			}
			edges = append(edges, link)
		}
	}
	return
}

type projectServiceInstanceLinker struct {
	probe *Probe
}

func (l *projectServiceInstanceLinker) GetABLinks(pjNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	pjID, err := pjNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}

	siIDs, err := probe.client.ListServiceInstanceIDs()
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}

	for _, siID := range siIDs {
		si, err := probe.client.GetServiceInstance(siID)
		if err != nil {
			logging.GetLogger().Error(err)
			return
		}
		for _, uuid := range si.ListProjectIDs() {
			if uuid == pjID {
				if siNode, _ := probe.siIndexer.GetNode(siID); siNode != nil {
					link, err := topology.NewLink(probe.graph, pjNode, siNode, "ownership", nil)
					if err != nil {
						logging.GetLogger().Error(err)
						continue
					}
					edges = append(edges, link)
				}
			}
		}
	}
	return
}

func (l *projectServiceInstanceLinker) GetBALinks(siNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	siID, err := siNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	si, err := probe.client.GetServiceInstance(siID)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	for _, pjID := range si.ListProjectIDs() {
		if pjNode, _ := probe.pjIndexer.GetNode(pjID); pjNode != nil {
			link, err := topology.NewLink(probe.graph, pjNode, siNode, "ownership", nil)
			if err != nil {
				logging.GetLogger().Error(err)
				continue
			}
			edges = append(edges, link)
		}
	}
	return
}

type projectVirtualNetworkLinker struct {
	probe *Probe
}

func (l *projectVirtualNetworkLinker) GetABLinks(pjNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	pjID, err := pjNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	pj, err := probe.client.GetProject(pjID)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	for _, vnID := range pj.ListVirtualNetworkIDs() {
		if vnNode, _ := probe.vnIndexer.GetNode(vnID); vnNode != nil {
			link, err := topology.NewLink(probe.graph, pjNode, vnNode, "ownership", nil)
			if err != nil {
				logging.GetLogger().Error(err)
				continue
			}
			edges = append(edges, link)
		}
	}
	return
}

func (l *projectVirtualNetworkLinker) GetBALinks(vnNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	vnID, err := vnNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	vn, err := probe.client.GetVirtualNetwork(vnID)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	for _, pjID := range vn.ListProjectIDs() {
		if pjNode, _ := probe.pjIndexer.GetNode(pjID); pjNode != nil {
			link, err := topology.NewLink(probe.graph, pjNode, vnNode, "ownership", nil)
			if err != nil {
				logging.GetLogger().Error(err)
				continue
			}
			edges = append(edges, link)
		}
	}
	return
}

type portTupleVirtualMachineInterfaceLinker struct {
	probe *Probe
}

func (l *portTupleVirtualMachineInterfaceLinker) GetABLinks(ptNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	ptID, err := ptNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	pt, err := probe.client.GetPortTuple(ptID)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	for _, vmiID := range pt.ListVirtualMachineInterfaceIDs() {
		if vmiNode, _ := probe.vmiIndexer.GetNode(vmiID); vmiNode != nil {
			link, err := topology.NewLink(probe.graph, ptNode, vmiNode, "ownership", nil)
			if err != nil {
				logging.GetLogger().Error(err)
				continue
			}
			edges = append(edges, link)
		}
	}
	return
}

func (l *portTupleVirtualMachineInterfaceLinker) GetBALinks(vmiNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	vmiID, err := vmiNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	vmi, err := probe.client.GetVirtualMachineInterface(vmiID)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	for _, ptID := range vmi.ListPortTupleIDs() {
		if ptNode, _ := probe.ptIndexer.GetNode(ptID); ptNode != nil {
			link, err := topology.NewLink(probe.graph, ptNode, vmiNode, "ownership", nil)
			if err != nil {
				logging.GetLogger().Error(err)
				continue
			}
			edges = append(edges, link)
		}
	}
	return
}

type serviceInstancePortTupleLinker struct {
	probe *Probe
}

func (l *serviceInstancePortTupleLinker) GetABLinks(siNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	siID, err := siNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	si, err := probe.client.GetServiceInstance(siID)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	for _, ptID := range si.ListPortTupleIDs() {
		if ptNode, _ := probe.ptIndexer.GetNode(ptID); ptNode != nil {
			link, err := topology.NewLink(probe.graph, siNode, ptNode, "ownership", nil)
			if err != nil {
				logging.GetLogger().Error(err)
				continue
			}
			edges = append(edges, link)
		}
	}
	return
}

func (l *serviceInstancePortTupleLinker) GetBALinks(ptNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	ptID, err := ptNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	pt, err := probe.client.GetPortTuple(ptID)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	for _, siID := range pt.ListServiceInstanceIDs() {
		if siNode, _ := probe.siIndexer.GetNode(siID); siNode != nil {
			link, err := topology.NewLink(probe.graph, siNode, ptNode, "ownership", nil)
			if err != nil {
				logging.GetLogger().Error(err)
				continue
			}
			edges = append(edges, link)
		}
	}
	return
}

type serviceInstanceVirtualNetworkLinker struct {
	probe *Probe
}

func (l *serviceInstanceVirtualNetworkLinker) GetABLinks(siNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	siID, err := siNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	si, err := probe.client.GetServiceInstance(siID)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	for _, vnFqName := range si.ListVirtualNetworks() {
		vnID, err := probe.client.FqNameToUUID(vnFqName, "virtual-network")
		if err != nil {
			logging.GetLogger().Error(err)
			return
		}
		if vnNode, _ := probe.vnIndexer.GetNode(vnID); vnNode != nil {
			link, err := topology.NewLink(probe.graph, siNode, vnNode, "attach-to", nil)
			if err != nil {
				logging.GetLogger().Error(err)
				continue
			}
			edges = append(edges, link)
		}
	}
	return
}

func (l *serviceInstanceVirtualNetworkLinker) GetBALinks(vnNode *graph.Node) (edges []*graph.Edge) {
	probe := l.probe
	vnID, err := vnNode.GetFieldString("UUID")
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}

	siIDs, err := probe.client.ListServiceInstanceIDs()
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}

	for _, siID := range siIDs {
		si, err := probe.client.GetServiceInstance(siID)
		if err != nil {
			logging.GetLogger().Error(err)
			return
		}
		for _, fqName := range si.ListVirtualNetworks() {
			uuid, err := probe.client.FqNameToUUID(fqName, "virtual-network")
			if err != nil {
				logging.GetLogger().Error(err)
				return
			}
			if uuid == vnID {
				if siNode, _ := probe.siIndexer.GetNode(siID); siNode != nil {
					link, err := topology.NewLink(probe.graph, vnNode, siNode, "attach-to", nil)
					if err != nil {
						logging.GetLogger().Error(err)
						continue
					}
					edges = append(edges, link)
				}
			}
		}
	}
	return
}
