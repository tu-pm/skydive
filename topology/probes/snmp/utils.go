package snmp

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/skydive-project/skydive/topology/probes/lldp"

	"github.com/google/gopacket/layers"

	"github.com/pkg/errors"
	"github.com/skydive-project/skydive/graffiti/graph"
)

func (p *Probe) updateMetadata(node *graph.Node, m graph.Metadata) {
	tr := p.graph.StartMetadataTransaction(node)
	for k, v := range m {
		tr.AddMetadata(k, v)
	}
	tr.Commit()
}

// Generate switch id
func genSwitchID(info *LLDPMetadata) (graph.Identifier, error) {
	if ip := net.ParseIP(info.MgmtAddress); ip == nil {
		return "", fmt.Errorf("Switch %s doesn't have an IP management address", info.SysName)
	}
	// Generate ChassisID from its metadata
	return graph.GenID(info.SysName, "SysName", info.MgmtAddress, "MgmtAddress"), nil
}

// Generate switch metadata
func genSwitchMetadata(m *LLDPMetadata) (id graph.Identifier, metadata graph.Metadata, err error) {
	// Generate ID
	id, err = genSwitchID(m)
	if err != nil {
		return
	}
	metadata = graph.Metadata{
		"LLDP":  (*lldp.Metadata)(m),
		"Name":  m.SysName,
		"Probe": "lldp",
		"State": lldp.SwitchUP,
		"Type":  "switch",
	}
	return
}

// Generate port id
func genPortID(swID graph.Identifier, port *LLDPMetadata) (graph.Identifier, error) {
	return graph.GenID(string(swID), port.PortID, port.PortIDType), nil
}

// Generate port metadata
func genPortMetadata(swID graph.Identifier, m *LLDPMetadata) (id graph.Identifier, metadata graph.Metadata, err error) {
	// Generate ID
	id, err = genPortID(swID, m)
	if err != nil {
		return
	}
	name := m.PortID
	// Use port description if port id is not interface name
	if ifstr := layers.LLDPPortIDSubtypeIfaceName; m.PortIDType != ifstr.String() {
		name = m.Description
	}
	metadata = graph.Metadata{
		"LLDP":  (*lldp.Metadata)(m),
		"Name":  name,
		"Probe": "lldp",
		"Type":  "switchport",
	}
	return
}

// Get list of management addresses
func (p *Probe) mgmtAddrs(reachableOnly bool) (addrs []string) {
	p.graph.RLock()
	switches := p.graph.GetNodes(graph.Metadata{"Type": "switch"})
	p.graph.RUnlock()
	for _, sw := range switches {
		state, _ := sw.GetFieldString("State")
		if reachableOnly == true && state != "UP" {
			continue
		}
		addr, err := sw.GetFieldString("LLDP.MgmtAddress")
		if err != nil || net.ParseIP(addr) == nil {
			continue
		}
		addrs = append(addrs, addr)
	}
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
	for k, v := range LldpLocalPortOIDs {
		oids[k] = fmt.Sprintf("%s.%d", v, portIndex)
	}
	return oids
}
