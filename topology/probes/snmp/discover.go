package snmp

import (
	"fmt"
	"github.com/skydive-project/skydive/topology/probes/lldp"

	"github.com/pkg/errors"
	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/logging"
	"github.com/skydive-project/skydive/topology"
	"github.com/soniah/gosnmp"
)

type remoteInfo struct {
	remAddr string
	remPort string
}

type lldpResponse struct {
	address string
	info    *LLDPMetadata
	links   map[string]remoteInfo
	ports   map[string]*LLDPMetadata
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
	sysInfo := &LLDPMetadata{}
	err = client.GetMany(LldpLocalChassisOIDs, sysInfo)
	if err != nil {
		res.err = err
		return res
	}
	sysInfo.Set("MgmtAddress", target)

	// Retrieve links to remote switches
	links := make(map[string]remoteInfo)
	locPorts := make(map[string]*LLDPMetadata)
	remPortOID := LldpRemotePortIDOID
	err = client.Walk(
		LldpRemoteChassisMgmtAddressOID,
		func(pdu gosnmp.SnmpPDU) error {
			// Get local port index
			locIndex, err := getIfIndex(pdu.Name)
			if err != nil {
				return err
			}
			// Get local port information from local port index
			locPort := &LLDPMetadata{}
			err = client.GetMany(genLocPortOIDs(locIndex), locPort)
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
			remPortIDString, ok := remPortID.(string)
			if !ok {
				return fmt.Errorf("remote port id type mismatch, id=%+v, type=%T", remPortID, remPortID)
			}
			// Ignore entries refer to the same address as current node
			if remAddr != target {
				locPorts[locPort.PortID] = locPort
				links[locPort.PortID] = remoteInfo{remAddr, remPortIDString}
			}
			remPortOID = nextOID
			return nil
		})
	if err != nil {
		res.err = err
		return res
	}
	res.info = sysInfo
	res.ports = locPorts
	res.links = links
	return res
}

func (p *Probe) updateSubGraph(resp *lldpResponse) {
	p.graph.Lock()
	defer p.graph.Unlock()
	swNode := p.graph.LookupFirstNode(graph.Metadata{"LLDP.MgmtAddress": resp.address, "Type": "switch"})
	// Unable to request lldp information from switch
	if resp.err != nil {
		if swNode == nil {
			logging.GetLogger().Debugf("Failed to fetch lldp information from address %s: %v", resp.address, resp.err)
			return
		}
		logging.GetLogger().Errorf("SNMP disconnected from switch %s: %v", resp.address, resp.err)
		p.graph.AddMetadata(swNode, "State", lldp.SwitchInaccessible)
		isDown := true
		for _, port := range p.graph.LookupChildren(swNode, graph.Metadata{"Type": "switchport"}, nil) {
			// If port doesn't have an ACTIVE link, continue
			edge := topology.GetFirstEdge(p.graph, port, graph.Metadata{"RelationType": "layer2", "State": lldp.LinkActive})
			if edge == nil {
				continue
			}
			// If port connects to another switch, and that switch is not accessible, continue
			remPort := topology.GetPeer(p.graph, port, edge, graph.Metadata{"Type": "switchport"})
			if remPort != nil {
				remSwitch := p.graph.LookupParents(remPort, graph.Metadata{"Type": "switch"}, topology.OwnershipMetadata())
				if len(remSwitch) > 0 {
					if state, _ := remSwitch[0].GetFieldString("State"); state != lldp.SwitchUP {
						continue
					}
				}
			}
			// Port still has an active link connecting to an accessible switch => switch is not down yet
			isDown = false
			break
		}
		if isDown {
			p.graph.AddMetadata(swNode, "State", lldp.SwitchDOWN)
			for _, port := range p.graph.LookupChildren(swNode, nil, topology.OwnershipMetadata()) {
				p.graph.AddMetadata(port, "State", "DOWN")
			}
		}
		return
	}
	swID, swMeta, err := genSwitchMetadata(resp.info)
	if err != nil {
		logging.GetLogger().Error(err)
		return
	}
	// Create or update switch
	if swNode == nil {
		swNode, err = p.graph.NewNode(swID, swMeta)
		if err != nil {
			if err != graph.ErrNodeConflict {
				err = errors.Wrapf(err, "Create switch node %s failed", swID)
				logging.GetLogger().Error(err)
			}
			return
		}
	} else {
		p.updateMetadata(swNode, swMeta)
	}
	for portID, portInfo := range resp.ports {
		locPort := p.graph.LookupFirstNode(graph.Metadata{"LLDP.PortID": portID, "Type": "switchport"})
		pID, pMeta, err := genPortMetadata(swID, portInfo)
		if err != nil {
			logging.GetLogger().Error(err)
			continue
		}
		// Create or update port
		if locPort == nil {
			locPort, err = p.graph.NewNode(pID, pMeta)
			if err != nil {
				if err != graph.ErrNodeConflict {
					err = errors.Wrapf(err, "Create port node %s failed", pID)
					logging.GetLogger().Error(err)
				}
				return
			}
		} else {
			p.updateMetadata(locPort, pMeta)
		}
		// Link switch to port
		if !topology.HaveOwnershipLink(p.graph, swNode, locPort) {
			topology.AddOwnershipLink(p.graph, swNode, locPort, nil)
		}
		remSwitch := p.graph.LookupFirstNode(graph.Metadata{
			"Type":             "switch",
			"LLDP.MgmtAddress": resp.links[portID].remAddr,
		})
		if remSwitch == nil {
			continue
		}
		remPort := p.graph.LookupFirstChild(remSwitch, graph.Metadata{
			"Type":        "switchport",
			"LLDP.PortID": resp.links[portID].remPort,
		})
		if remPort == nil {
			continue
		}
		l2Link := topology.GetFirstEdge(p.graph, locPort, topology.Layer2Metadata())
		if l2Link != nil {
			curRemPort := topology.GetPeer(p.graph, locPort, l2Link, nil)
			if curRemPort != nil && curRemPort.ID != remPort.ID {
				p.graph.Unlink(locPort, curRemPort)
				l2Link = nil
			}
		}
		if l2Link == nil {
			topology.AddLayer2Link(p.graph, remPort, locPort, graph.Metadata{"State": lldp.LinkActive})
		} else {
			p.graph.AddMetadata(l2Link, "State", lldp.LinkActive)
		}
	}
	for _, portNode := range p.graph.LookupChildren(swNode, graph.Metadata{"Type": "switchport"}, nil) {
		// Ignore if LLDP.PortID is reported in lldp response
		id, _ := portNode.GetFieldString("LLDP.PortID")
		if _, ok := resp.ports[id]; ok {
			continue
		}
		// Ignore if port doesn't have a layer2 link
		link := topology.GetFirstEdge(p.graph, portNode, topology.Layer2Metadata())
		if link == nil {
			continue
		}
		// Ignore if remote port doesn't belong to a switch
		remPort := topology.GetPeer(p.graph, portNode, link, graph.Metadata{"Type": "switchport"})
		if remPort == nil {
			continue
		}
		// Set l2 link to INACTIVE
		p.graph.AddMetadata(link, "State", lldp.LinkInactive)
	}
}

func (p *Probe) discoverFabricTopo() {
	var (
		discovered   = make(map[string]struct{})
		respChan     = make(chan *lldpResponse)
		neighborChan = make(chan []string)
	)

	go func() {
		for resp := range respChan {
			p.updateSubGraph(resp)
		}
	}()

	// While there're still non-visited addresses
	for addrs := p.mgmtAddrs(false); len(addrs) > 0; {
		// Use multiple snmp clients, one for each address, to request lldp information
		for _, addr := range addrs {
			go func(target string) {
				var remAddrs []string
				res := lldpRequest(target, p.community)
				for _, link := range res.links {
					remAddrs = append(remAddrs, link.remAddr)
				}
				respChan <- res
				neighborChan <- remAddrs
			}(addr)
		}
		// Main goroutine wait and get data from all clients
		var newAddrs []string
		for i := 0; i < len(addrs); i++ {
			for _, addr := range <-neighborChan {
				// Add addr to discovered addresses list
				if _, ok := discovered[addr]; !ok {
					newAddrs = append(newAddrs, addr)
					discovered[addr] = struct{}{}
				}
			}
		}
		logging.GetLogger().Debug("Discovered new addresses: %v", newAddrs)
		addrs = newAddrs
	}
	close(respChan)
}
