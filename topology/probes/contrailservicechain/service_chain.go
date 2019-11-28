package contrailservicechain

import (
	"context"
	"net/http"
	"sync"

	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/logging"
	"github.com/skydive-project/skydive/probe"
	"github.com/skydive-project/skydive/topology"
	"github.com/skydive-project/skydive/topology/probes"
	"github.com/skydive-project/skydive/topology/probes/contrailservicechain/types"
)

type sfcEvent func()

type Probe struct {
	graph.ListenerHandler
	graph     *graph.Graph
	client    RestApiClient
	eventChan chan sfcEvent
	bundle    *probe.Bundle
	// Domain Indexer
	dmIndexer *graph.Indexer
	// Project Indexer
	pjIndexer *graph.Indexer
	// Service Instance Indexer
	siIndexer *graph.Indexer
	// Virtual Network Indexer
	vnIndexer *graph.Indexer
	// Port Tuple Indexer
	ptIndexer *graph.Indexer
	// Virtual Machine Interface Indexer
	vmiIndexer *graph.Indexer
	// Domain-Project Linker
	dmpjLinker *graph.ResourceLinker
	// Project-ServiceInstance Linker
	pjsiLinker *graph.ResourceLinker
	// Project-VirtualNetwork Linker
	pjvnLinker *graph.ResourceLinker
	// PortTuple-VirtualMachineInterface Linker
	ptvmiLinker *graph.ResourceLinker
	// ServiceInstance-PortTuple Linker
	siptLinker *graph.ResourceLinker
	// ServiceInstance-VirtualNetwork Linker
	sivnLinker *graph.ResourceLinker
}

func (p *Probe) addServiceChainLink(idxr1, idxr2 *graph.Indexer, uuid1, uuid2 string, metadata graph.Metadata) {
	// logging.GetLogger().Debugf("Discover new service chain link from UUID %s to UUID %s", uuid1, uuid2)
	p.graph.Lock()
	node1, _ := idxr1.GetNode(uuid1)
	node2, _ := idxr2.GetNode(uuid2)
	if node1 != nil && node2 != nil {
		topology.AddLink(p.graph, node1, node2, "servicechain", metadata)
	}
	p.graph.Unlock()
}

func (p *Probe) registerNode(indexer *graph.Indexer, uuid string, metadata graph.Metadata) {
	// logging.GetLogger().Debugf("Registering Contrail SFC object with type %s, UUID %s and metadata %+v", metadata["Type"], uuid, metadata)

	p.graph.Lock()
	defer p.graph.Unlock()

	id := graph.GenID(uuid)
	node, _ := indexer.GetNode(uuid)
	if node == nil {
		n, err := p.graph.NewNode(id, metadata)
		if err != nil {
			logging.GetLogger().Error(err)
			return
		}
		node = n
	} else {
		p.graph.SetMetadata(node, metadata)
	}

	indexer.Index(id, node, map[string]interface{}{uuid: node})
}

func (p *Probe) unregisterNode(indexer *graph.Indexer, uuid string) {
	logging.GetLogger().Debugf("Unregistering SFC object with UUID %s", uuid)

	p.graph.Lock()
	defer p.graph.Unlock()

	node, _ := indexer.GetNode(uuid)
	if node != nil {
		p.graph.DelNode(node)
		indexer.Unindex(node.ID, node)
	}
}

func (p *Probe) OnDomainCreate(dm types.Domain) {
	p.eventChan <- func() {
		p.registerNode(p.dmIndexer, dm.UUID, domainMetadata(dm))
	}
}

func (p *Probe) OnDomainDelete(dm types.Domain) {
	p.eventChan <- func() { p.unregisterNode(p.dmIndexer, dm.UUID) }
}

func (p *Probe) OnProjectCreate(pj types.Project) {
	p.eventChan <- func() {
		p.registerNode(p.pjIndexer, pj.UUID, projectMetadata(pj))
	}
}

func (p *Probe) OnProjectDelete(pj types.Project) {
	p.eventChan <- func() { p.unregisterNode(p.pjIndexer, pj.UUID) }
}

func (p *Probe) OnServiceInstanceCreate(si types.ServiceInstance, st types.ServiceTemplate) {
	p.eventChan <- func() {
		p.registerNode(p.siIndexer, si.UUID, serviceInstanceMetadata(si, st))
	}
	// go func() {
	ptIDs := si.ListPortTupleIDs()
	for _, ptID := range ptIDs {
		pt, err := p.client.GetPortTuple(ptID)
		if err != nil {
			logging.GetLogger().Error(err)
			return
		}
		p.OnPortTupleCreate(pt)
	}
	// }()
}

func (p *Probe) OnServiceInstanceDelete(si types.ServiceInstance) {
	p.eventChan <- func() { p.unregisterNode(p.siIndexer, si.UUID) }
}

func (p *Probe) OnPortTupleCreate(pt types.PortTuple) {
	p.eventChan <- func() {
		p.registerNode(p.ptIndexer, pt.UUID, portTupleMetadata(pt))
	}
	// go func() {
	vmiIDs := pt.ListVirtualMachineInterfaceIDs()
	for _, vmiID := range vmiIDs {
		vmi, err := p.client.GetVirtualMachineInterface(vmiID)
		if err != nil {
			logging.GetLogger().Error(err)
			return
		}
		p.OnVirtualMachineInterfaceCreate(vmi)
	}
	// }()
}

func (p *Probe) OnPortTupleDelete(pt types.PortTuple) {
	p.eventChan <- func() { p.unregisterNode(p.ptIndexer, pt.UUID) }
}

func (p *Probe) OnVirtualNetworkCreate(vn types.VirtualNetwork) {
	p.eventChan <- func() { p.registerNode(p.vnIndexer, vn.UUID, virtualNetworkMetadata(vn)) }
}

func (p *Probe) OnVirtualNetworkDelete(vn types.VirtualNetwork) {
	p.eventChan <- func() { p.unregisterNode(p.vnIndexer, vn.UUID) }
}

func (p *Probe) OnVirtualMachineInterfaceCreate(vmi types.VirtualMachineInterface) {
	p.eventChan <- func() { p.registerNode(p.vmiIndexer, vmi.UUID, virtualMachineInterfaceMetadata(vmi)) }
}

func (p *Probe) OnVirtualMachineInterfaceDelete(vmi types.VirtualMachineInterface) {
	p.eventChan <- func() { p.unregisterNode(p.vmiIndexer, vmi.UUID) }
}

func (p *Probe) OnServiceChainLinkCreate(idxr1, idxr2 *graph.Indexer, uuid1, uuid2 string, m graph.Metadata) {
	p.eventChan <- func() {
		p.addServiceChainLink(idxr1, idxr2, uuid1, uuid2, m)
	}
}

func (p *Probe) OnError(err error) {
	logging.GetLogger().Error(err)
}

func (p *Probe) createSFCLinks() error {
	policies, _ := p.client.ListNetworkPolicys()
	for _, policy := range policies {
		ruleTargets, _ := p.client.ExtractRuleTargets(policy)
		for _, rt := range ruleTargets {
			siIDs := rt.ServiceInstanceIDs
			if len(siIDs) == 0 {
				continue
			}
			metadata := networkPolicyRuleMetadata(rt.Rule)
			metadata.SetField("PolicyName", policy.FqName)
			metadata.SetField("PolicyID", policy.UUID)
			first, last := siIDs[0], siIDs[len(siIDs)-1]
			// Link service instances in appearance order
			for i, siID := range siIDs[0 : len(siIDs)-1] {
				p.OnServiceChainLinkCreate(p.siIndexer, p.siIndexer, siID, siIDs[i+1], metadata)
			}
			// Link all source virtual networks to the first service instance
			for _, vnID := range rt.SourceVnIDs {
				vnNode, _ := p.vnIndexer.GetNode(vnID)
				if vnNode == nil {
					vn, _ := p.client.GetVirtualNetwork(vnID)
					p.OnVirtualNetworkCreate(vn)
				}
				p.OnServiceChainLinkCreate(p.vnIndexer, p.siIndexer, vnID, first, metadata)
			}
			// Link all destination virtual networks to the last service instance
			for _, vnID := range rt.DestinationVnIDs {
				vnNode, _ := p.vnIndexer.GetNode(vnID)
				if vnNode == nil {
					vn, _ := p.client.GetVirtualNetwork(vnID)
					p.OnVirtualNetworkCreate(vn)
				}
				p.OnServiceChainLinkCreate(p.vnIndexer, p.siIndexer, vnID, last, metadata)
			}
		}
	}
	return nil
}

func (p *Probe) Do(ctx context.Context, wg *sync.WaitGroup) error {
	logging.GetLogger().Debugf("Refreshing SFC Topology")
	p.bundle.Start()
	p.eventChan = make(chan sfcEvent, 100)

	// Create domain nodes
	domains, err := p.client.ListDomains()
	if err != nil {
		logging.GetLogger().Error(err)
		return err
	}
	for _, domain := range domains {
		p.OnDomainCreate(domain)
	}

	// Create project nodes
	projects, err := p.client.ListProjects()
	if err != nil {
		logging.GetLogger().Error(err)
		return err
	}
	for _, project := range projects {
		p.OnProjectCreate(project)
	}

	// Create service instance nodes
	serviceInstances, err := p.client.ListServiceInstances()
	if err != nil {
		logging.GetLogger().Error(err)
		return err
	}
	for _, si := range serviceInstances {
		stIDs := si.ListServiceTemplateIDs()
		if len(stIDs) == 0 {
			continue
		}
		st, err := p.client.GetServiceTemplate(stIDs[0])
		if err != nil {
			logging.GetLogger().Error(err)
			return err
		}
		p.OnServiceInstanceCreate(si, st)
	}

	p.createSFCLinks()
	close(p.eventChan)

	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
			p.bundle.Stop()
		}()

		for {
			select {
			case eventCallback, ok := <-p.eventChan:
				if !ok {
					return
				}
				eventCallback()
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

func NewProbe(g *graph.Graph) (probe.Handler, error) {
	p := &Probe{
		graph:      g,
		client:     RestApiClient{&http.Client{}, "http://10.60.17.231:8082"},
		dmIndexer:  graph.NewIndexer(g, nil, uuidHasher, false),
		ptIndexer:  graph.NewIndexer(g, nil, uuidHasher, false),
		vmiIndexer: graph.NewIndexer(g, nil, uuidHasher, false),
		vnIndexer:  graph.NewIndexer(g, nil, uuidHasher, false),
		siIndexer:  graph.NewIndexer(g, nil, uuidHasher, false),
		pjIndexer:  graph.NewIndexer(g, nil, uuidHasher, false),
	}

	p.bundle = &probe.Bundle{
		Handlers: map[string]probe.Handler{
			"dmIndexer":  p.dmIndexer,
			"ptIndexer":  p.ptIndexer,
			"vmiIndexer": p.vmiIndexer,
			"vnIndexer":  p.vnIndexer,
			"siIndexer":  p.siIndexer,
			"pjIndexer":  p.pjIndexer,
		},
	}

	p.dmpjLinker = graph.NewResourceLinker(g,
		[]graph.ListenerHandler{p.dmIndexer},
		[]graph.ListenerHandler{p.pjIndexer},
		&domainProjectLinker{probe: p}, nil)
	p.bundle.AddHandler("dmpjLinker", p.dmpjLinker)

	p.pjsiLinker = graph.NewResourceLinker(g,
		[]graph.ListenerHandler{p.pjIndexer},
		[]graph.ListenerHandler{p.siIndexer},
		&projectServiceInstanceLinker{probe: p}, nil)
	p.bundle.AddHandler("pjsiLinker", p.pjsiLinker)

	p.pjvnLinker = graph.NewResourceLinker(g,
		[]graph.ListenerHandler{p.pjIndexer},
		[]graph.ListenerHandler{p.vnIndexer},
		&projectVirtualNetworkLinker{probe: p}, nil)
	p.bundle.AddHandler("pjvnLinker", p.pjvnLinker)

	p.ptvmiLinker = graph.NewResourceLinker(g,
		[]graph.ListenerHandler{p.ptIndexer},
		[]graph.ListenerHandler{p.vmiIndexer},
		&portTupleVirtualMachineInterfaceLinker{probe: p}, nil)
	p.bundle.AddHandler("ptvmiLinker", p.ptvmiLinker)

	p.siptLinker = graph.NewResourceLinker(g,
		[]graph.ListenerHandler{p.siIndexer},
		[]graph.ListenerHandler{p.ptIndexer},
		&serviceInstancePortTupleLinker{probe: p}, nil)
	p.bundle.AddHandler("siptLinker", p.siptLinker)

	p.sivnLinker = graph.NewResourceLinker(g,
		[]graph.ListenerHandler{p.siIndexer},
		[]graph.ListenerHandler{p.vnIndexer},
		&serviceInstanceVirtualNetworkLinker{probe: p}, nil)
	p.bundle.AddHandler("sivnLinker", p.sivnLinker)

	p.dmpjLinker.AddEventListener(p)
	p.pjsiLinker.AddEventListener(p)
	p.pjvnLinker.AddEventListener(p)
	p.ptvmiLinker.AddEventListener(p)
	p.siptLinker.AddEventListener(p)
	p.sivnLinker.AddEventListener(p)

	return probes.NewProbeWrapper(p), nil
}

func uuidHasher(n *graph.Node) map[string]interface{} {
	if uuid, err := n.GetFieldString("UUID"); err != nil {
		return map[string]interface{}{uuid: nil}
	}
	return nil
}
