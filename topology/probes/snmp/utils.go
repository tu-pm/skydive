package snmp

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/logging"
	"github.com/skydive-project/skydive/topology/probes/lldp"
)

func (p *Probe) createNode(id graph.Identifier, m graph.Metadata) *graph.Node {
	node, err := p.graph.NewNode(id, m)
	if err != nil {
		logging.GetLogger().Error(err)
	}
	return node
}

func (p *Probe) updateMetadata(node *graph.Node, m graph.Metadata) {
	tr := p.graph.StartMetadataTransaction(node)
	for k, v := range m {
		tr.AddMetadata(k, v)
	}
	tr.Commit()
}

// Generate switch metadata
func genSwitchMetadata(m *Payload) graph.Metadata {
	lldpInfo := &lldp.Metadata{}
	m.InitStruct(lldpInfo)
	return graph.Metadata{
		"LLDP":      lldpInfo,
		"Name":      lldpInfo.SysName,
		"Probe":     "lldp",
		"SNMPState": "UP",
		"Type":      "switch",
	}
}

// Generate port metadata
func genPortMetadata(m *Payload) graph.Metadata {
	lldpInfo := &lldp.Metadata{}
	m.InitStruct(lldpInfo)
	if lldpInfo.PortIDType != "Interface Name" {
		panic(fmt.Sprintf("Failed to create port %+v: PortIDType must be Interface Name", *m))
	}
	return graph.Metadata{
		"LLDP":  lldpInfo,
		"Name":  lldpInfo.PortID,
		"Probe": "lldp",
		"Type":  "switchport",
	}
}

// Generate switch id
func genSwitchID(m *Payload) graph.Identifier {
	if len((*m)["MgmtAddress"].(string)) == 0 {
		panic(fmt.Sprintf("Switch %+v doesn't have a management address", *m))
	}
	sysName, ok := (*m)["SysName"].(string)
	if !ok {
		panic(fmt.Sprintf("Switch %+v sysname is not a string", *m))
	}
	mgmtAddress, ok := (*m)["MgmtAddress"].(string)
	if !ok {
		panic(fmt.Sprintf("Switch %+v mgmt address is not a string", *m))
	}
	// Generate ChassisID from its metadata
	return graph.GenID(sysName, "SysName", mgmtAddress, "MgmtAddress")
}

// Generate port id
func genPortID(switchID string, port *Payload) graph.Identifier {
	portID, ok := (*port)["PortID"].(string)
	if !ok {
		panic(fmt.Sprintf("Port %+v ID is not a string", *port))
	}
	portIDType, ok := (*port)["PortIDType"].(string)
	if !ok {
		panic(fmt.Sprintf("Port %+v ID Type is not a string", *port))
	}
	return graph.GenID(switchID, portID, portIDType)
}

// Get list of management addresses
func (p *Probe) mgmtAddrs(reachableOnly bool) (addrs []string) {
	p.graph.RLock()
	switches := p.graph.GetNodes(graph.Metadata{"Type": "switch"})
	for _, sw := range switches {
		snmpState, _ := sw.GetFieldString("SNMPState")
		if reachableOnly == true && snmpState == "DOWN" {
			continue
		}
		addr, err := sw.GetFieldString("LLDP.MgmtAddress")
		if err != nil || net.ParseIP(addr) == nil {
			continue
		}
		addrs = append(addrs, addr)
	}
	p.graph.RUnlock()
	return
}

// Extract Address from LldpRemoteChassisMgmtAddressOID
func getRemAddr(oid string) (remAddr string, err error) {
	slice := strings.Split(oid, ".")
	remAddr = strings.Join(slice[len(slice)-4:], ".")
	if net.ParseIP(remAddr) == nil {
		err = errors.New("Invalid IP address")
	}
	return
}

// Extract IfIndex from LldpRemoteChassisMgmtAddressOID
func getIfIndex(oid string) (locIfIndex int, err error) {
	offset := len(strings.Split(LldpRemoteChassisMgmtAddressOID, "."))
	slice := strings.Split(oid, ".")[offset:]
	locIfIndex, err = strconv.Atoi(slice[1])
	return
}

// Generate local port's absolute OIDs from index
func genLocPortOIDs(portIndex int) map[string]string {
	oids := make(map[string]string)
	for k, v := range LldpLocalPortOIDsMinimum {
		oids[k] = fmt.Sprintf("%s.%d", v, portIndex)
	}
	return oids
}
