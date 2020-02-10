package snmp

import (
	"fmt"

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
	info    *Payload
	links   map[string]remoteInfo
	ports   map[string]*Payload
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
	locPorts := make(map[string]*Payload)
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

			// Bug type conversion error
			locPortIDString, ok := (*locPort)["PortID"].(string)
			if !ok {
				panic(fmt.Sprintf("local port id type mismatch, locport=%+v", *locPort))
			}
			remPortIDString, ok := remPortID.(string)
			if !ok {
				panic(fmt.Sprintf("remote port id type mismatch, id=%+v, type=%T", remPortID, remPortID))
			}
			// If two switches are stacked together, each pair of stacked ports will have
			// two port connecting to each other by a layer2 link. They then exchange
			// LLDP messages between themselves, results in two rows in the LldpRemAddr Table
			// having the same address as the switch's management address.
			// Here we just ignore such cases to avoid further confusions
			if remAddr != target {
				locPorts[locPortIDString] = locPort
				links[locPortIDString] = remoteInfo{remAddr, remPortIDString}
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

func (p *Probe) topoFabricUpdater(respChan <-chan *lldpResponse) {
	for resp := range respChan {
		p.graph.Lock()
		swNode := p.graph.LookupFirstNode(graph.Metadata{"LLDP.MgmtAddress": resp.address, "Type": "switch"})
		// Unable to request lldp information from switch
		if resp.err != nil {
			logging.GetLogger().Errorf("Failed to fetch lldp information from switch %s: %v", resp.address, resp.err)
			if swNode != nil {
				p.graph.AddMetadata(swNode, "SNMPState", "DOWN")
			}
			p.graph.Unlock()
			continue
		}
		// Create or update switch
		swID := genSwitchID(resp.info)
		if sm := genSwitchMetadata(resp.info); swNode == nil {
			swNode = p.createNode(swID, sm)
		} else {
			p.updateMetadata(swNode, sm)
		}
		for portID, portInfo := range resp.ports {
			// Create or update port
			locPort := p.graph.LookupFirstNode(graph.Metadata{"LLDP.PortID": portID, "Type": "switchport"})
			if lm := genPortMetadata(portInfo); locPort == nil {
				locPort = p.createNode(genPortID(string(swID), portInfo), lm)
			} else {
				p.updateMetadata(locPort, lm)
			}
			// Link switch to port
			if !topology.HaveOwnershipLink(p.graph, swNode, locPort) {
				topology.AddOwnershipLink(p.graph, swNode, locPort, nil)
			}
			remPortID := resp.links[portID].remPort
			// If local port is currently linked to a different remote port => delete that link
			if curRemport := p.graph.LookupFirstChild(locPort, topology.Layer2Metadata()); curRemport != nil {
				if curRemPortID, _ := curRemport.GetFieldString("LLDP.PortID"); curRemPortID != remPortID {
					p.graph.Unlink(locPort, curRemport)
				}
			}
			// Link local port to remote port if presented
			remPort := p.graph.LookupFirstNode(graph.Metadata{
				"Type":        "switchport",
				"LLDP.PortID": remPortID,
			})
			if remPort != nil && !topology.HaveLayer2Link(p.graph, remPort, locPort) {
				topology.AddLayer2Link(p.graph, remPort, locPort, nil)
			}
		}
		p.graph.Unlock()
	}
}

func (p *Probe) discoverFabricTopo() {
	discovered := make(Set)
	respChan := make(chan *lldpResponse)
	neighborChan := make(chan []string)
	go p.topoFabricUpdater(respChan)

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
		var neighbors []string
		for i := 0; i < len(addrs); i++ {
			// Pull the next message from channel
			neighbors = append(neighbors, <-neighborChan...)
		}
		// Discover new chassises
		addrs = discovered.Push(neighbors)
	}
	close(respChan)
}
