package snmp

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/skydive-project/skydive/common"
	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/probe"
	"github.com/skydive-project/skydive/topology"
	tp "github.com/skydive-project/skydive/topology/probes"
	"github.com/skydive-project/skydive/topology/probes/lldp"
	"github.com/soniah/gosnmp"
)

type Probe struct {
	sync.RWMutex
	graph.DefaultGraphListener
	Ctx        tp.Context
	state      common.ServiceState // state of the probe (running or stopped)
	wg         sync.WaitGroup      // capture goroutines wait group
	quit       chan bool
	community  string
	target     string
	refreshing int
	sampling   int
}

type lldpResponse struct {
	chassis  *SnmpPayload
	remPorts map[string]*SnmpPayload
	err      error
}

type ifResponse struct {
	address string
	status  map[string]*SnmpPayload
	metrics map[string]*SnmpPayload
	err     error
}

func lldpRequest(target, community string) *lldpResponse {
	res := &lldpResponse{}

	// Connect to target
	snmpClient := NewSnmpClient(target, community)
	err := snmpClient.Connect()
	if err != nil {
		res.err = err
		return res
	}
	defer snmpClient.Close()

	// Retrieve local system information
	resChassis, err := snmpClient.Get(LldpLocalChassisOIDs)
	if err != nil {
		res.err = err
		return res
	}
	resChassis.SetValue("MgmtAddress", target)

	// Retrieve remote ports information
	resRemPorts := make(map[string]*SnmpPayload)
	remPortOIDs := LldpRemotePortOIDsMinimum
	err = snmpClient.Walk(
		LldpRemoteChassisMgmtAddressOID,
		func(pdu gosnmp.SnmpPDU) error {
			// Extract the management address of remote switch
			neighbor := getIPv4(pdu.Name)
			// Get remote ports infomation
			nextOIDs, remport, err := snmpClient.GetNext(remPortOIDs)
			if err != nil {
				return err
			}
			resRemPorts[neighbor] = remport
			remPortOIDs = nextOIDs
			return nil
		})
	if err != nil {
		res.err = err
		return res
	}
	res.chassis = resChassis
	res.remPorts = resRemPorts
	return res
}

func ifRequest(target, community string) *ifResponse {
	res := &ifResponse{
		address: target,
	}

	// Connect to target
	var snmpClient = NewSnmpClient(target, community)
	err := snmpClient.Connect()
	if err != nil {
		res.err = err
		return res
	}
	defer snmpClient.Close()

	// Request metrics and status of each interface
	resStatuses := make(map[string]*SnmpPayload)
	resMetrics := make(map[string]*SnmpPayload)
	metricOIDs, statusOIDs := IfMetricOIDs, IfStatusOIDs
	err = snmpClient.Walk(
		IfDescrOID,
		func(pdu gosnmp.SnmpPDU) error {
			// Get port description to make it portMetrics' key
			descr, err := snmpClient.getPDUValue(pdu)
			if err != nil {
				return err
			}
			// Get port status
			nextStatusOIDs, status, err := snmpClient.GetNext(statusOIDs)
			if err != nil {
				return err
			}
			resStatuses[descr.(string)] = status

			// Retrieve port's metrics
			nextMetricOIDs, metric, err := snmpClient.GetNext(metricOIDs)
			if err != nil {
				return err
			}
			metric.SetValue("Start", int64(0))
			metric.SetValue("Last", int64(0))
			resMetrics[descr.(string)] = metric

			metricOIDs, statusOIDs = nextMetricOIDs, nextStatusOIDs
			return nil
		},
	)
	if err != nil {
		res.err = err
		return res
	}
	res.status = resStatuses
	res.metrics = resMetrics
	return res
}

func (p *Probe) gatherLldpInfo() (map[string]*lldpResponse, error) {
	responses := make(map[string]*lldpResponse)
	discovered := make(Set)
	ch := make(chan *lldpResponse)

	// While there're still non-visited addresses
	for addrs := []string{p.target}; len(addrs) > 0; {
		// Use multiple snmp clients, one for each address, to request
		// lldp information
		for _, addr := range addrs {
			go func(target, community string, ch chan *lldpResponse) {
				res := lldpRequest(target, community)
				ch <- res
			}(addr, p.community, ch)
		}
		// Main goroutine wait and get data from all clients
		neighbors := []string{}
		for i := 0; i < len(addrs); i++ {
			// Pull the next message from channel ch
			res := <-ch
			if res.err != nil {
				return make(map[string]*lldpResponse), res.err
			}
			// Add the response to responses map
			addr := (*res.chassis)["MgmtAddress"]
			responses[addr.(string)] = res
			// Store neighbors of neighbor
			for neighbor := range res.remPorts {
				neighbors = append(neighbors, neighbor)
			}
		}
		// Discover new chassises
		addrs = discovered.Push(neighbors)
	}

	// Enforce symetricity of the responses map. That means all remote chassis
	// must also have a link to the current one
	for addr, res := range responses {
		for remAddr, _ := range res.remPorts {
			if _, ok := responses[remAddr].remPorts[addr]; !ok {
				delete(res.remPorts, remAddr)
			}
		}
	}
	return responses, nil
}

func (p *Probe) deleteMissingNodes(responses map[string]*lldpResponse) error {
	// Delete missing nodes and nodes with edited ID fields
	g := p.Ctx.Graph
	for _, chassisNode := range g.GetNodes(graph.Metadata{"Type": "switch"}) {
		addr, err := chassisNode.GetFieldString("LLDP.MgmtAddress")
		if err != nil {
			return err
		}
		locPorts := g.LookupChildren(chassisNode, nil, graph.Metadata{"RelationType": "ownership"})
		res, ok := responses[addr]
		if !ok || chassisNode.ID != genChassisID(res.chassis) {
			// if a chassis node is missing, or its ID fields get updated, delete it and all of its interfaces
			for _, port := range locPorts {
				err := g.DelNode(port)
				if err != nil {
					return err
				}
			}
			err := g.DelNode(chassisNode)
			if err != nil {
				return err
			}
		} else {
			for _, locPortNode := range locPorts {
				remPortNode := g.LookupFirstChild(locPortNode, graph.Metadata{"Type": "switchport"})
				if remPortNode == nil {
					continue
				}
				remChassisNode := g.LookupFirstChild(remPortNode, graph.Metadata{"Type": "switch"})
				if remChassisNode == nil {
					continue
				}
				remAddr, err := remChassisNode.GetFieldString("LLDP.MgmtAddress")
				if err != nil {
					return err
				}
				// check if remote port appears in new chassises
				remPortInfo, ok := responses[addr].remPorts[remAddr]
				if !ok || remPortNode.ID != genLldpPortID(responses[remAddr].chassis, remPortInfo) {
					// Delete missing remote port
					err := g.DelNode(remPortNode)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (p *Probe) refreshLldpTopo(responses map[string]*lldpResponse) {
	g := p.Ctx.Graph
	for addr, res := range responses {
		chassisLldpMetadata := &lldp.Metadata{}
		res.chassis.InitStruct(chassisLldpMetadata)
		chassisMetadata := graph.Metadata{
			"LLDP":  chassisLldpMetadata,
			"Name":  chassisLldpMetadata.SysName,
			"Probe": "lldp",
			"Type":  "switch",
		}
		// Get current chassis node
		locChassis := p.getOrCreate(
			genChassisID(res.chassis),
			chassisMetadata,
		)
		for remAddr, remPortInfo := range res.remPorts {
			// Create localPort node
			locPortLldpMetadata := &lldp.Metadata{}
			locPortInfo := responses[remAddr].remPorts[addr]
			locPortInfo.InitStruct(locPortLldpMetadata)
			locPortMetadata := graph.Metadata{
				"LLDP":  locPortLldpMetadata,
				"Name":  locPortLldpMetadata.Description,
				"Probe": "lldp",
				"Type":  "switchport",
			}
			locPort := p.getOrCreate(
				genLldpPortID(res.chassis, locPortInfo),
				locPortMetadata,
			)

			// Create remotePort node
			remPortLldpMetadata := &lldp.Metadata{}
			remPortInfo.InitStruct(remPortLldpMetadata)
			remPortMetadata := graph.Metadata{
				"LLDP":  remPortLldpMetadata,
				"Name":  remPortLldpMetadata.Description,
				"Probe": "lldp",
				"Type":  "switchport",
			}
			remPort := p.getOrCreate(
				genLldpPortID(responses[remAddr].chassis, remPortInfo),
				remPortMetadata,
			)

			// Update topology
			if !topology.HaveOwnershipLink(g, locChassis, locPort) {
				topology.AddOwnershipLink(g, locChassis, locPort, nil)
				// topology.AddLayer2Link(g, locChassis, locPort, nil)
			}
			if !topology.HaveLayer2Link(g, locPort, remPort) {
				topology.AddLayer2Link(g, locPort, remPort, nil)
			}
		}
	}
}

func (p *Probe) updateIfMetrics(portNode *graph.Node, portMetrics *SnmpPayload, now, last time.Time) {
	g := p.Ctx.Graph
	// Update port metrics and status
	tr := g.StartMetadataTransaction(portNode)
	newMetric := &topology.ChassisInterfaceMetric{}
	portMetrics.InitStruct(newMetric)

	// Update port metrics
	if newMetric == nil || newMetric.IsZero() {
		return
	}
	newMetric.Last = int64(common.UnixMillis(now))
	currMetric, err := portNode.GetField("ChassisIfMetric")
	var lastUpdateMetric *topology.ChassisInterfaceMetric
	if err == nil {
		lastUpdateMetric = newMetric.Sub(
			currMetric.(*topology.ChassisInterfaceMetric),
		).(*topology.ChassisInterfaceMetric)
	}
	if lastUpdateMetric != nil && lastUpdateMetric.IsZero() {
		// nothing changed since last update
		return
	}
	tr.AddMetadata("ChassisIfMetric", newMetric)
	if lastUpdateMetric != nil {
		lastUpdateMetric.Start = int64(common.UnixMillis(last))
		lastUpdateMetric.Last = int64(common.UnixMillis(now))
		tr.AddMetadata("LastUpdateChassisIfMetric", lastUpdateMetric)
	}

	tr.Commit()
}

func (p *Probe) updateIfInfo(now, last time.Time) {
	chassisNodes := p.Ctx.Graph.GetNodes(graph.Metadata{"Type": "switch"})
	ch := make(chan *ifResponse)

	// Iterate through discovered chassis nodes
	for _, chassisNode := range chassisNodes {
		addr, _ := chassisNode.GetFieldString("LLDP.MgmtAddress")
		// Use one goroutine to send snmp request to each chassis address
		go func(target, community string, ch chan *ifResponse) {
			res := ifRequest(target, community)
			ch <- res
		}(addr, p.community, ch)
	}

	// Main goroutine wait and get data from all clients
	for i := 0; i < len(chassisNodes); i++ {
		// Pull the next message from channel ch
		res := <-ch
		if res.err != nil {
			p.Ctx.Logger.Error(res.err)
			continue
		}
		// Get the chassis node using res.address
		var chassisNode *graph.Node
		nodes := p.Ctx.Graph.GetNodes(graph.Metadata{"LLDP.MgmtAddress": res.address})
		if len(nodes) > 0 {
			chassisNode = nodes[0]
		}

		// Create a mapping between lldp port description and port node
		for portDescr, portMetadata := range res.status {
			var portID graph.Identifier
			// WARNING: There might be more than one node, must list all portNode with the same name and delete the unwanted ones
			matcher := graph.Metadata{
				"Type": "switchport",
				"Name": portDescr,
			}
			dupPorts := p.Ctx.Graph.LookupChildren(chassisNode, matcher, nil)
			switch len(dupPorts) {
			// No port with given name existed, create new one
			case 0:
				if portDescr == "ens11" || portDescr == "ens10" {
					debug(0, portDescr, matcher)
				}
				portID = genLocalPortID(chassisNode, portDescr)
				portMetadata.SetValue("Name", portDescr)
				portMetadata.SetValue("Probe", "snmp")
				portMetadata.SetValue("Type", "switchport")
				break

			// There's already a port with the given name, just retrieve that port
			case 1:
				if portDescr == "ens11" || portDescr == "ens10" {
					debug(1, portDescr, matcher)
				}
				portID = dupPorts[0].ID
				break

			// There are two ports, the first one was created by the snmp probe and the second one by the lldp probe
			// => Delete the snmp port and return the lldp port
			case 2:
				if portDescr == "ens11" || portDescr == "ens10" {
					debug(2, portDescr, matcher)
				}
				p.Ctx.Graph.DelNode(dupPorts[0])
				portID = dupPorts[1].ID

			// There shouldn't be more than two ports with the same name existed
			default:
				p.Ctx.Logger.Errorf("There's multiple port existed with name %s on switch %s", portDescr, chassisNode)
				continue
			}
			portNode := p.getOrCreate(portID, graph.Metadata(*portMetadata))
			if !topology.HaveOwnershipLink(p.Ctx.Graph, chassisNode, portNode) {
				topology.AddOwnershipLink(p.Ctx.Graph, chassisNode, portNode, nil)
				// topology.AddLayer2Link(g, chassisNode, portNode, nil)
			}
			p.updateIfMetrics(portNode, res.metrics[portDescr], now, last)
		}
	}
}

func (p *Probe) getOrCreate(id graph.Identifier, m graph.Metadata) *graph.Node {
	node := p.Ctx.Graph.GetNode(id)
	if node == nil {
		var err error

		node, err = p.Ctx.Graph.NewNode(id, m)
		if err != nil {
			p.Ctx.Logger.Error(err)
		}
	} else {
		tr := p.Ctx.Graph.StartMetadataTransaction(node)
		for k, v := range m {
			tr.AddMetadata(k, v)
		}
		tr.Commit()
	}
	return node
}

func genChassisID(m *SnmpPayload) graph.Identifier {
	// Generate ChassisID from its metadata
	return graph.GenID(
		(*m)["SysName"].(string),
		"SysName",
		(*m)["MgmtAddress"].(string),
		"MgmtAddress",
	)
}

func genLocalPortID(chassis *graph.Node, portDescr string) graph.Identifier {
	return graph.GenID(
		string(chassis.ID),
		"Description",
		portDescr,
	)
}

func genLldpPortID(chassis, port *SnmpPayload) graph.Identifier {
	return graph.GenID(
		string(genChassisID(chassis)),
		(*port)["PortID"].(string),
		(*port)["PortIDType"].(string),
	)
}

func (p *Probe) Start() {
	p.state.Store(common.RunningState)
	p.Ctx.Graph.AddEventListener(p)
	p.Ctx.Graph.RLock()
	defer p.Ctx.Graph.RUnlock()
	p.Lock()
	defer p.Unlock()

	go func() {
		refreshTicker := time.NewTicker(time.Duration(p.refreshing) * time.Second)
		sampleTicker := time.NewTicker(time.Duration(p.sampling) * time.Second)
		last := time.Now().UTC()
		for {
			select {
			case <-refreshTicker.C:
				fmt.Println("Refreshing...")
				responses, err := p.gatherLldpInfo()
				if err != nil {
					p.Ctx.Logger.Error(err)
				}

				p.Ctx.Graph.Lock()
				err = p.deleteMissingNodes(responses)
				if err != nil {
					p.Ctx.Logger.Error(err)
				}
				p.refreshLldpTopo(responses)
				p.Ctx.Graph.Unlock()

			case t := <-sampleTicker.C:
				fmt.Println("Updating...")
				p.Ctx.Graph.Lock()
				now := t.UTC()
				p.updateIfInfo(now, last)
				last = now
				p.Ctx.Graph.Unlock()

			case <-p.quit:
				return
			}
		}
	}()
}

func (p *Probe) Stop() {
	p.quit <- true
	p.Ctx.Graph.RemoveEventListener(p)
	p.state.Store(common.StoppingState)
	p.Ctx.Logger.Debugf("Stopping SNMP probe")
	p.wg.Wait()
}

// Init initializes a new SNMP probe
func (p *Probe) Init(ctx tp.Context, bundle *probe.Bundle) (probe.Handler, error) {
	p.community = ctx.Config.GetString("agent.topology.snmp.community")
	p.target = ctx.Config.GetString("agent.topology.snmp.target")
	p.refreshing = ctx.Config.GetInt("agent.topology.snmp.refreshing")
	p.sampling = ctx.Config.GetInt("agent.topology.snmp.sampling")
	p.Ctx = ctx
	p.state = common.StoppedState
	p.quit = make(chan bool)
	return p, nil
}

func getIPv4(oid string) string {
	slice := strings.Split(oid, ".")
	slice = slice[len(slice)-4:]
	return strings.Join(slice, ".")
}

func debug(x ...interface{}) {
	fmt.Printf(">> DEBUG: ")
	fmt.Println(x...)
	fmt.Println()
}
