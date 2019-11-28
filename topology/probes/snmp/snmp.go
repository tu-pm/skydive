package snmp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/skydive-project/skydive/common"
	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/logging"
	"github.com/skydive-project/skydive/probe"
	"github.com/skydive-project/skydive/topology"
	"github.com/skydive-project/skydive/topology/probes"
	"github.com/skydive-project/skydive/topology/probes/lldp"
	"github.com/soniah/gosnmp"
)

type Probe struct {
	graph      *graph.Graph
	community  string
	target     string
	lastUpdate time.Time
}

type lldpResponse struct {
	address  string
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
	res := &lldpResponse{address: target}

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

func (p *Probe) gatherLldpInfo() map[string]*lldpResponse {
	responses := make(map[string]*lldpResponse)
	discovered := make(Set)
	ch := make(chan *lldpResponse)

	// While there're still non-visited addresses
	for addrs := []string{p.target}; len(addrs) > 0; {
		// Use multiple snmp clients, one for each address, to request
		// lldp information
		for _, addr := range addrs {
			go func(target string) {
				res := lldpRequest(target, p.community)
				ch <- res
			}(addr)
		}
		// Main goroutine wait and get data from all clients
		neighbors := []string{}
		for i := 0; i < len(addrs); i++ {
			// Pull the next message from channel ch
			res := <-ch
			// Add the response to responses map
			responses[res.address] = res
			if res.err != nil {
				logging.GetLogger().Error(res.err)
				continue
			}
			// Store neighbors of neighbor
			for neighbor := range res.remPorts {
				neighbors = append(neighbors, neighbor)
			}
		}
		// Discover new chassises
		addrs = discovered.Push(neighbors)
	}

	return responses
}

func (p *Probe) queryIfInfo(addrs []string) (responses []*ifResponse) {
	ch := make(chan *ifResponse)
	for _, addr := range addrs {
		// Use one goroutine to send snmp request to each chassis address
		go func(target string) {
			res := ifRequest(target, p.community)
			ch <- res
		}(addr)
	}

	// Main goroutine wait and get data from all clients
	for i := 0; i < len(addrs); i++ {
		// Pull the next message from channel ch
		res := <-ch
		// Get the chassis node using res.address
		responses = append(responses, res)
	}
	return
}

// Update changes in the topology layout gathered from lldp requests
// Covered cases are:
// 1. Unable to request LLDP information from a switch -> Set its SNMP state to DOWN
// 2. Switch's SysName changes, causing its ID to change -> Delete it to create a new one
// 3. Link from remote port to local port is missing -> Delete the link between them
func (p *Probe) updateLldpElems(responses map[string]*lldpResponse) {
	g := p.graph
	for _, locChassisNode := range g.GetNodes(graph.Metadata{"Type": "switch"}) {
		addr, _ := locChassisNode.GetFieldString("LLDP.MgmtAddress")
		locChassis, ok := responses[addr]
		// 1. If local chassis doesn't appear, set its state to DOWN
		if !ok || locChassis.err != nil {
			p.graph.AddMetadata(locChassisNode, "SNMPState", "DOWN")
			continue
		}
		locPorts := g.LookupChildren(locChassisNode, graph.Metadata{"Type": "switchport"}, nil)
		// 2. If local chassis ID has changed, remove it to create a new one
		if locChassisNode.ID != genChassisID(locChassis.chassis) {
			fmt.Printf("ID CHANGED: Chassis node %v\n", locChassisNode)
			for _, port := range locPorts {
				err := g.DelNode(port)
				if err != nil {
					logging.GetLogger().Error(err)
				}
			}
			err := g.DelNode(locChassisNode)
			if err != nil {
				logging.GetLogger().Error(err)
			}
			continue
		}
		for _, locPortNode := range locPorts {
			// Get current remote port and remote chassis node
			remPortNode := g.LookupFirstChild(locPortNode, graph.Metadata{"Type": "switchport"})
			if remPortNode == nil {
				continue
			}
			remChassisNode := g.LookupFirstChild(remPortNode, graph.Metadata{"Type": "switch"})
			if remChassisNode == nil {
				continue
			}
			// If remote chassis does not appear, just continue
			remAddr, _ := remChassisNode.GetFieldString("LLDP.MgmtAddress")
			remChassis, ok := responses[remAddr]
			if !ok {
				continue
			}
			// 3. If remote port does not have a link to local port, delete the existed link
			locPortInfo, ok := remChassis.remPorts[remAddr]
			if !ok || locPortNode.ID != genLldpPortID(locChassis.chassis, locPortInfo) {
				edge := g.GetFirstLink(locPortNode, remPortNode, topology.Layer2Metadata())
				lp, _ := locPortNode.GetFieldString("Name")
				rp, _ := remPortNode.GetFieldString("Name")
				lc, _ := locChassisNode.GetFieldString("Name")
				rc, _ := remChassisNode.GetFieldString("Name")
				fmt.Printf("LINK MISSING: Port %s on switch %s to port %s on switch %s\n", rp, rc, lp, lc)
				err := g.DelEdge(edge)
				if err != nil {
					logging.GetLogger().Error(err)
				}
			}
		}
	}
}

// Add new nodes and links from lldp responses
func (p *Probe) addLldpElems(responses map[string]*lldpResponse) {
	nodeLinks := make(map[string]map[string]*graph.Node)
	chassisNodes := make(map[string]*graph.Node)
	for addr, res := range responses {
		if res.err != nil {
			continue
		}
		// Create or update chassis node
		chassisLldpMetadata := &lldp.Metadata{}
		res.chassis.InitStruct(chassisLldpMetadata)
		chassisMetadata := graph.Metadata{
			"LLDP":      chassisLldpMetadata,
			"Name":      chassisLldpMetadata.SysName,
			"Probe":     "lldp",
			"Type":      "switch",
			"SNMPState": "UP",
		}
		locChassisNode := p.getOrCreate(genChassisID(res.chassis), chassisMetadata)
		chassisNodes[addr] = locChassisNode
		// Create or update remote ports
		for remAddr, portInfo := range res.remPorts {
			remChassis, ok := responses[remAddr]
			if !ok || remChassis.err != nil {
				continue
			}
			portLldpMetadata := &lldp.Metadata{}
			portInfo.InitStruct(portLldpMetadata)
			var portName string
			if portLldpMetadata.PortIDType == "Interface Name" {
				portName = portLldpMetadata.PortID
			} else {
				portName = portLldpMetadata.Description
			}
			portMetadata := graph.Metadata{
				"LLDP":  portLldpMetadata,
				"Name":  portName,
				"Probe": "lldp",
				"Type":  "switchport",
			}
			remPortNode := p.getOrCreate(
				genLldpPortID(remChassis.chassis, portInfo),
				portMetadata,
			)
			if nodeLinks[remAddr] == nil {
				nodeLinks[remAddr] = make(map[string]*graph.Node)
			}
			nodeLinks[remAddr][addr] = remPortNode
		}
	}
	for addr, links := range nodeLinks {
		chassis := chassisNodes[addr]
		for remAddr, port := range links {
			if !topology.HaveOwnershipLink(p.graph, chassis, port) {
				topology.AddOwnershipLink(p.graph, chassis, port, nil)
			}
			remChassisLinks, ok := nodeLinks[remAddr]
			if !ok {
				continue
			}
			remPort, ok := remChassisLinks[addr]
			if !ok {
				continue
			}
			if !topology.HaveLayer2Link(p.graph, remPort, port) {
				topology.AddLayer2Link(p.graph, remPort, port, nil)
			}
		}
	}
}

func (p *Probe) updateIfMetrics(portNode *graph.Node, portMetrics *SnmpPayload, now, last time.Time) {
	g := p.graph
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

func (p *Probe) updateIfInfo(ifResponses []*ifResponse, now, last time.Time) {
	// Main goroutine wait and get data from all clients
	for _, res := range ifResponses {
		var chassisNode *graph.Node
		nodes := p.graph.GetNodes(graph.Metadata{"LLDP.MgmtAddress": res.address})
		if len(nodes) > 0 {
			chassisNode = nodes[0]
		}
		// Set SNMPState to DOWN if unable to request SNMP information
		if res.err != nil {
			p.graph.AddMetadata(chassisNode, "SNMPState", "DOWN")
			logging.GetLogger().Error(res.err)
			continue
		}
		// Keep track on ports that will be updated
		updatedPorts := make(map[graph.Identifier]bool)
		for _, portNode := range p.graph.LookupChildren(chassisNode, graph.Metadata{"Type": "switchport"}, nil) {
			updatedPorts[portNode.ID] = false
		}
		// Update metadata and metrics for each port
		for portDescr, portMetadata := range res.status {
			var portID graph.Identifier
			matcher := graph.Metadata{
				"Type": "switchport",
				"Name": portDescr,
			}
			dupPorts := p.graph.LookupChildren(chassisNode, matcher, nil)
			if len(dupPorts) == 0 {
				// If port didn't exist, create it
				portID = genLocalPortID(chassisNode, portDescr)
				portMetadata.SetValue("Name", portDescr)
				portMetadata.SetValue("Probe", "snmp")
				portMetadata.SetValue("Type", "switchport")
			} else {
				// If there are multiple ports exised, take the newest one
				var t1 time.Time
				for _, port := range dupPorts {
					if t2 := time.Time(port.CreatedAt); t2.After(t1) {
						t1 = t2
						portID = port.ID
					}
				}
			}
			portNode := p.getOrCreate(portID, graph.Metadata(*portMetadata))
			if !topology.HaveOwnershipLink(p.graph, chassisNode, portNode) {
				topology.AddOwnershipLink(p.graph, chassisNode, portNode, nil)
			}
			p.updateIfMetrics(portNode, res.metrics[portDescr], now, last)
			updatedPorts[portNode.ID] = true
		}
		// If there are ports that didn't get updated, indicating that switch can no longer detect them -> Remove them from the graph
		for id, updated := range updatedPorts {
			if !updated {
				lc, _ := chassisNode.GetFieldString("Name")
				lp, _ := p.graph.GetNode(id).GetFieldString("Name")
				fmt.Printf("Port %s on switch %s doesn't get updated\n", lp, lc)
				p.graph.DelNode(p.graph.GetNode(id))
			}
		}
	}
}

func (p *Probe) getOrCreate(id graph.Identifier, m graph.Metadata) *graph.Node {
	node := p.graph.GetNode(id)
	if node == nil {
		var err error

		node, err = p.graph.NewNode(id, m)
		if err != nil {
			logging.GetLogger().Error(err)
		}
	} else {
		tr := p.graph.StartMetadataTransaction(node)
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
		// "Description",
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

func (p *Probe) Do(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Add(1)
	go func() {
		lldpResponses := p.gatherLldpInfo()

		// Update graph using lldp metadata
		fmt.Println("Refreshing...")
		p.graph.Lock()
		p.updateLldpElems(lldpResponses)
		p.addLldpElems(lldpResponses)
		p.graph.Unlock()

		// Extract discovered switches' MgmtAddress
		p.graph.RLock()
		var addrs []string
		switches := p.graph.GetNodes(graph.Metadata{"Type": "switch"})
		for _, sw := range switches {
			addr, err := sw.GetFieldString("LLDP.MgmtAddress")
			if err == nil {
				addrs = append(addrs, addr)
			}
		}
		p.graph.RUnlock()

		// Query switch and ports statistics
		ifResponses := p.queryIfInfo(addrs)
		// Update graph using if metadata
		fmt.Println("Updating...")
		now := time.Now().UTC()
		p.graph.Lock()
		p.updateIfInfo(ifResponses, now, p.lastUpdate)
		p.graph.Unlock()
		p.lastUpdate = now

		wg.Done()
	}()
	return nil
}

// Init initializes a new SNMP probe
func NewProbe(g *graph.Graph, community, target string, refreshing, sampling int) (probe.Handler, error) {
	p := &Probe{
		graph:      g,
		community:  community,
		target:     target,
		lastUpdate: time.Now().UTC(),
	}
	return probes.NewProbeWrapper(p), nil
}

func getIPv4(oid string) string {
	slice := strings.Split(oid, ".")
	slice = slice[len(slice)-4:]
	return strings.Join(slice, ".")
}
