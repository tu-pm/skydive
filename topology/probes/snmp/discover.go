package snmp

import (
	"fmt"

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
		logging.GetLogger().Errorf("Failed to fetch lldp information from switch %s: %v", resp.address, resp.err)
		if swNode != nil {
			p.graph.AddMetadata(swNode, "SNMPState", "DOWN")
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
			locPort, _ = p.graph.NewNode(pID, pMeta)
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
