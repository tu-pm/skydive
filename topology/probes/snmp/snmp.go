package snmp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/skydive-project/skydive/common"
	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/logging"
	"github.com/skydive-project/skydive/probe"
	"github.com/skydive-project/skydive/topology"
	"github.com/skydive-project/skydive/topology/probes"
	"github.com/skydive-project/skydive/topology/probes/lldp"
	"github.com/soniah/gosnmp"
)

// Probe implements the SNMP probe
type Probe struct {
	graph      *graph.Graph
	community  string
	target     string
	lastUpdate time.Time
}

type remoteInfo struct {
	remAddr string
	remPort string
}

type lldpResponse struct {
	address  string
	sysInfo  *SnmpPayload
	links    map[string]remoteInfo
	locPorts map[string]*SnmpPayload
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
	client := NewSnmpClient(target, community)
	err := client.Connect()
	if err != nil {
		res.err = err
		return res
	}
	defer client.Close()

	// Retrieve local system information
	sysInfo, err := client.GetMany(LldpLocalChassisOIDs)
	if err != nil {
		res.err = err
		return res
	}
	sysInfo.SetValue("MgmtAddress", target)

	// Retrieve links to remote switches
	links := make(map[string]remoteInfo)
	locPorts := make(map[string]*SnmpPayload)
	remPortOID := LldpRemotePortIdOID
	err = client.Walk(
		LldpRemoteChassisMgmtAddressOID,
		func(pdu gosnmp.SnmpPDU) error {
			// Get local port index
			locIndex, err := getIfIndex(pdu.Name)
			if err != nil {
				return err
			}
			// Get local port information from local port index
			locPort, err := client.GetMany(genLocPortOIDs(locIndex))
			if err != nil {
				return err
			}
			// Get remote address
			remAddr, err := getRemAddr(pdu.Name)
			if err != nil {
				return err
			}
			// Get remote ports infomation
			nextOID, remPortID, err := client.GetNext(remPortOID)
			if err != nil {
				return err
			}
			// Ignore stacking ports
			if remAddr != target {
				locPortID := (*locPort)["PortID"].(string)
				locPorts[locPortID] = locPort
				links[locPortID] = remoteInfo{remAddr, remPortID.(string)}
			}
			remPortOID = nextOID
			return nil
		})
	if err != nil {
		res.err = err
		return res
	}
	res.sysInfo = sysInfo
	res.locPorts = locPorts
	res.links = links
	return res
}

func ifRequest(target, community string) *ifResponse {
	res := &ifResponse{
		address: target,
	}

	// Connect to target
	client := NewSnmpClient(target, community)
	err := client.Connect()
	if err != nil {
		res.err = err
		return res
	}
	defer client.Close()

	// Request metrics and status of each interface
	resStatuses := make(map[string]*SnmpPayload)
	resMetrics := make(map[string]*SnmpPayload)
	metricOIDs, statusOIDs := IfMetricOIDs, IfStatusOIDs
	err = client.Walk(
		IfDescrOID,
		func(pdu gosnmp.SnmpPDU) error {
			// Get port description to make it portMetrics' key
			descr, err := client.getPDUValue(pdu)
			if err != nil {
				return err
			}
			// Get port status
			nextStatusOIDs, status, err := client.GetNextMany(statusOIDs)
			if err != nil {
				return err
			}
			resStatuses[descr.(string)] = status

			// Retrieve port's metrics
			nextMetricOIDs, metric, err := client.GetNextMany(metricOIDs)
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
	for addrs := p.mgmtAddrs(); len(addrs) > 0; {
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
			for _, link := range res.links {
				neighbors = append(neighbors, link.remAddr)
			}
		}
		// Discover new chassises
		addrs = discovered.Push(neighbors)
	}

	return responses
}

func (p *Probe) queryIfInfo() (responses []*ifResponse) {
	addrs := p.mgmtAddrs()
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
// 3. Link from local port to remote port is missing -> Delete the link between them
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
		if locChassisNode.ID != p.genChassisID(locChassis.sysInfo) {
			for _, port := range locPorts {
				err := g.DelNode(port)
				if err != nil {
					logging.GetLogger().Error(err)
				}
			}
			name, _ := locChassisNode.GetFieldString("Name")
			logging.GetLogger().Infof(
				"Deleting switch %s. Reason: Switch's ID changed, delete to create a new one",
				name,
			)
			err := g.DelNode(locChassisNode)
			if err != nil {
				logging.GetLogger().Error(err)
			}
			continue
		}
		for _, locPortNode := range locPorts {
			// Get local port ID
			locPortID, _ := locPortNode.GetFieldString("LLDP.PortID")

			// Get remote port ID
			remPortNode := g.LookupFirstChild(locPortNode, graph.Metadata{"Type": "switchport"})
			if remPortNode == nil {
				continue
			}
			remPortID, _ := remPortNode.GetFieldString("LLDP.PortID")

			// 3. If local port is pointing to different remote port, delete the old link
			if remInfo, ok := locChassis.links[locPortID]; !ok || remInfo.remPort != remPortID {
				edge := g.GetFirstLink(locPortNode, remPortNode, topology.Layer2Metadata())
				g.DelEdge(edge)
			}
		}
	}
}

// Add new nodes and links from lldp responses
func (p *Probe) addLldpElems(responses map[string]*lldpResponse) {
	for _, res := range responses {
		if res.err != nil {
			continue
		}
		// Create or update chassis node
		chassisLldpMetadata := &lldp.Metadata{}
		res.sysInfo.InitStruct(chassisLldpMetadata)
		chassisMetadata := graph.Metadata{
			"LLDP":      chassisLldpMetadata,
			"Name":      chassisLldpMetadata.SysName,
			"Probe":     "lldp",
			"Type":      "switch",
			"SNMPState": "UP",
		}
		locChassisNode := p.getOrCreate(p.genChassisID(res.sysInfo), chassisMetadata)
		for portID, portInfo := range res.locPorts {
			// Create or update local port node
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
			locPortNode := p.getOrCreate(
				p.genLldpPortID(res.sysInfo, portInfo),
				portMetadata,
			)

			if !topology.HaveOwnershipLink(p.graph, locChassisNode, locPortNode) {
				topology.AddOwnershipLink(p.graph, locChassisNode, locPortNode, nil)
			}

			remPortNode := p.graph.LookupFirstNode(graph.Metadata{
				"Type":        "switchport",
				"LLDP.PortID": res.links[portID].remPort,
			})

			if remPortNode == nil {
				continue
			}

			if !topology.HaveLayer2Link(p.graph, remPortNode, locPortNode) {
				logging.GetLogger().Infof("Adding layer2 link from port %s to port %s", remPortNode.ID, locPortNode.ID)
				topology.AddLayer2Link(p.graph, remPortNode, locPortNode, nil)
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
		nodes := p.graph.GetNodes(graph.Metadata{"LLDP.MgmtAddress": res.address})
		if len(nodes) == 0 {
			continue
		}
		chassisNode := nodes[0]
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
				if len(dupPorts) > 1 {
					logging.GetLogger().Infof("DUPLICATED PORTS DETECTED:")
					logging.GetLogger().Info(dupPorts)
				}
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
				logging.GetLogger().Infof(
					"Deleting port %s on switch %s. Reason: ID changed", lp, lc)
				logging.GetLogger().Info(p.graph.GetNodes(graph.Metadata{"Name": lp}))
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

func (p *Probe) genChassisID(m *SnmpPayload) graph.Identifier {
	if len((*m)["MgmtAddress"].(string)) == 0 {
		nodes := p.graph.GetNodes(graph.Metadata{
			"Type": "switch",
			"Name": (*m)["SysName"].(string),
		})
		if len(nodes) > 0 {
			return nodes[0].ID
		}
	}
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

func (p *Probe) genLldpPortID(chassis, port *SnmpPayload) graph.Identifier {
	return graph.GenID(
		string(p.genChassisID(chassis)),
		(*port)["PortID"].(string),
		(*port)["PortIDType"].(string),
	)
}

func (p *Probe) mgmtAddrs() (addrs []string) {
	p.graph.RLock()
	switches := p.graph.GetNodes(graph.Metadata{"Type": "switch"})
	for _, sw := range switches {
		addr, err := sw.GetFieldString("LLDP.MgmtAddress")
		if err == nil && net.ParseIP(addr) != nil {
			addrs = append(addrs, addr)
		}
	}
	p.graph.RUnlock()
	return
}

// Get index of the local port receiving LLDP messages,
// as well as mgmt address of the switch sending them
func getRemAddr(oid string) (remAddr string, err error) {
	slice := strings.Split(oid, ".")
	remAddr = strings.Join(slice[len(slice)-4:], ".")
	if net.ParseIP(remAddr) == nil {
		err = errors.New("Invalid IP address")
	}
	return
}

// Get index of the local port receiving LLDP messages,
// as well as mgmt address of the switch sending them
func getIfIndex(oid string) (locIfIndex int, err error) {
	offset := len(strings.Split(LldpRemoteChassisMgmtAddressOID, "."))
	slice := strings.Split(oid, ".")[offset:]
	locIfIndex, err = strconv.Atoi(slice[1])
	return
}

// Generate port's absolute OIDs from index
func genLocPortOIDs(portIndex int) map[string]string {
	oids := make(map[string]string)
	for k, v := range LldpLocalPortOIDsMinimum {
		oids[k] = fmt.Sprintf("%s.%d", v, portIndex)
	}
	return oids
}

// Do implements main loop of the program
func (p *Probe) Do(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Add(1)
	go func() {

		lldpResponses := p.gatherLldpInfo()
		p.graph.Lock()
		p.updateLldpElems(lldpResponses)
		p.addLldpElems(lldpResponses)
		p.graph.Unlock()
		// // Query switch and ports statistics
		// ifResponses := p.queryIfInfo()
		// // Update graph using if metadata
		// now := time.Now().UTC()
		// p.graph.Lock()
		// p.updateIfInfo(ifResponses, now, p.lastUpdate)
		// p.graph.Unlock()
		// p.lastUpdate = now

		wg.Done()
	}()
	return nil
}

// NewProbe initializes a new SNMP probe
func NewProbe(g *graph.Graph, community, target string, refreshing, sampling int) (probe.Handler, error) {
	p := &Probe{
		graph:      g,
		community:  community,
		target:     target,
		lastUpdate: time.Now().UTC(),
	}
	return probes.NewProbeWrapper(p), nil
}
