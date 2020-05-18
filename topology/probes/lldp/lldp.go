// +build linux

/*
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy ofthe License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 */

package lldp

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/safchain/ethtool"
	"golang.org/x/sys/unix"

	"github.com/skydive-project/skydive/flow"
	"github.com/skydive-project/skydive/flow/probes"
	gp "github.com/skydive-project/skydive/flow/probes/gopacket"
	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/graffiti/service"
	"github.com/skydive-project/skydive/probe"
	"github.com/skydive-project/skydive/topology"
	tp "github.com/skydive-project/skydive/topology/probes"
)

/*
 #include <linux/if_packet.h>  // packet_mreq
 #include <linux/if_ether.h>  // ETH_ALEN
*/
import "C"

const lldpBPFFilter = `ether[0] & 1 = 1 and
   ether proto 0x88cc and
   !(ether src %s) and
   (ether dst 01:80:c2:00:00:0e or
	ether dst 01:80:c2:00:00:03 or
	ether dst 01:80:c2:00:00:00)`

// Capture 8192 bytes so that we have the full Ethernet frame
const lldpSnapLen = 8192

const (
	// LinkActive when there are LLDP packets sending through it
	LinkActive string = "ACTIVE"
	// LinkInactive when there is no LLDP packets sending through it
	LinkInactive string = "INACTIVE"
)

// Probe describes the probe that is in charge of listening for
// LLDP packets on interfaces and create the corresponding chassis and port nodes
type Probe struct {
	sync.RWMutex
	graph.DefaultGraphListener
	Ctx           tp.Context
	interfaceMap  map[string]*gp.Probe // map interface names to the packet probes
	state         service.State        // state of the probe (running or stopped)
	wg            sync.WaitGroup       // capture goroutines wait group
	autoDiscovery bool                 // capture LLDP traffic on all capable interfaces
	linkWatcher   *Watcher             // store the last moment an LLDP packet arrived on each link
}

// Watcher keeps track on frequently updated elements
type Watcher struct {
	sync.Mutex
	elements map[graph.Identifier]time.Time // map element's ID to last updated timestamp
	interval time.Duration                  // watcher interval
	timeout  time.Duration                  // elements become expired after timeout
	quit     chan bool                      // stop watcher
}

// Watch periodically looks for expired elements
func (w *Watcher) Watch(wg *sync.WaitGroup, expireFunc func(id graph.Identifier)) {
	ticker := time.NewTicker(w.interval)
	go func() {
		defer func() {
			ticker.Stop()
			wg.Done()
		}()
		for {
			select {
			case <-ticker.C:
				now := time.Now().UTC()
				for id, last := range w.elements {
					if now.Sub(last) < w.timeout {
						expireFunc(id)
					}
				}
			case <-w.quit:
				return
			}
		}
	}()
}

// Stop watcher loop
func (w *Watcher) Stop() {
	w.quit <- true
}

// Update store the last time an element gets updated
func (w *Watcher) Update(id graph.Identifier) {
	w.Lock()
	w.elements[id] = time.Now().UTC()
	w.Unlock()
}

// Drop lose track of an element
func (w *Watcher) Drop(id graph.Identifier) {
	w.Lock()
	delete(w.elements, id)
	w.Unlock()
}

type ifreq struct {
	ifrName   [ethtool.IFNAMSIZ]byte
	ifrHwaddr syscall.RawSockaddr
}

type lldpCapture struct{}

func (c *lldpCapture) OnStarted(*probes.CaptureMetadata) {
}

func (c *lldpCapture) OnStopped() {
}

func (c *lldpCapture) OnError(err error) {
}

// addMulticastAddr adds a multicast address to an interface using an ioctl call
func addMulticastAddr(intf string, addr string) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	var name [ethtool.IFNAMSIZ]byte
	copy(name[:], []byte(intf))

	mac, _ := net.ParseMAC(addr)
	ifr := &ifreq{
		ifrName:   name,
		ifrHwaddr: rawSocketaddrFromMAC(mac),
	}

	_, _, ep := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		unix.SIOCADDMULTI, uintptr(unsafe.Pointer(ifr)))

	if ep != 0 {
		return syscall.Errno(ep)
	}
	return nil
}

func (p *Probe) handlePacket(n *graph.Node, ifName string, packet gopacket.Packet) {
	lldpLayer := packet.Layer(layers.LayerTypeLinkLayerDiscovery)
	if lldpLayer != nil {
		lldpLayer := lldpLayer.(*layers.LinkLayerDiscovery)

		bytesToString := func(b []byte) string {
			return string(bytes.Trim(b, "\x00"))
		}

		chassisLLDPMetadata := &Metadata{
			ChassisIDType: lldpLayer.ChassisID.Subtype.String(),
		}

		chassisMetadata := graph.Metadata{
			"LLDP":  chassisLLDPMetadata,
			"Type":  "switch",
			"Probe": "lldp",
		}

		var chassisID string
		var chassisDiscriminators []string
		switch lldpLayer.ChassisID.Subtype {
		case layers.LLDPChassisIDSubTypeMACAddr:
			chassisID = net.HardwareAddr(lldpLayer.ChassisID.ID).String()
		default:
			chassisID = bytesToString(lldpLayer.ChassisID.ID)
		}
		chassisLLDPMetadata.ChassisID = chassisID
		chassisMetadata.SetField("Name", chassisID)

		portLLDPMetadata := &Metadata{
			PortIDType: lldpLayer.PortID.Subtype.String(),
		}
		portMetadata := graph.Metadata{
			"LLDP":  portLLDPMetadata,
			"Type":  "switchport",
			"Probe": "lldp",
		}

		var portID string
		switch lldpLayer.PortID.Subtype {
		case layers.LLDPPortIDSubtypeMACAddr:
			portID = net.HardwareAddr(lldpLayer.PortID.ID).String()
		default:
			portID = bytesToString(lldpLayer.PortID.ID)
		}
		portLLDPMetadata.PortID = portID
		portMetadata.SetField("Name", portID)

		if lldpLayerInfo := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo); lldpLayerInfo != nil {
			lldpLayerInfo := lldpLayerInfo.(*layers.LinkLayerDiscoveryInfo)

			if portDescription := lldpLayerInfo.PortDescription; portDescription != "" {
				portLLDPMetadata.Description = portDescription
				// Rename port to portDescription if portID is not InterfaceName
				if portIDSubtype := lldpLayer.PortID.Subtype; portIDSubtype != layers.LLDPPortIDSubtypeIfaceName {
					portMetadata["Name"] = bytesToString([]byte(portDescription))
				}
			}

			if lldpLayerInfo.SysDescription != "" {
				chassisLLDPMetadata.Description = bytesToString([]byte(lldpLayerInfo.SysDescription))
			}

			if sysName := bytesToString([]byte(lldpLayerInfo.SysName)); sysName != "" {
				chassisDiscriminators = append(chassisDiscriminators, sysName, "SysName")
				chassisLLDPMetadata.SysName = sysName
				chassisMetadata["Name"] = sysName
			}

			if mgmtAddress := lldpLayerInfo.MgmtAddress; len(mgmtAddress.Address) > 0 {
				var addr string
				switch mgmtAddress.Subtype {
				case layers.IANAAddressFamilyIPV4, layers.IANAAddressFamilyIPV6:
					addr = net.IP(mgmtAddress.Address).String()
				case layers.IANAAddressFamilyDistname:
					addr = bytesToString(mgmtAddress.Address)
				}

				if addr != "" {
					chassisDiscriminators = append(chassisDiscriminators, addr, "MgmtAddress")
					chassisLLDPMetadata.MgmtAddress = addr
				}
			}

			if lldp8201Q, err := lldpLayerInfo.Decode8021(); err == nil {
				if lldp8201Q.LinkAggregation.Supported {
					portLLDPMetadata.LinkAggregation = &LinkAggregationMetadata{
						Enabled:   lldp8201Q.LinkAggregation.Enabled,
						PortID:    int64(lldp8201Q.LinkAggregation.PortID),
						Supported: lldp8201Q.LinkAggregation.Supported,
					}
				}

				if lldp8201Q.PVID != 0 {
					portLLDPMetadata.PVID = int64(lldp8201Q.PVID)
				}

				if lldp8201Q.VIDUsageDigest != 0 {
					portLLDPMetadata.VIDUsageDigest = int64(lldp8201Q.VIDUsageDigest)
				}

				if lldp8201Q.ManagementVID != 0 {
					portLLDPMetadata.ManagementVID = int64(lldp8201Q.ManagementVID)
				}

				if len(lldp8201Q.VLANNames) != 0 {
					portLLDPMetadata.VLANNames = make([]VLANNameMetadata, len(lldp8201Q.VLANNames))
					for i, vlan := range lldp8201Q.VLANNames {
						portLLDPMetadata.VLANNames[i].ID = int64(vlan.ID)
						portLLDPMetadata.VLANNames[i].Name = bytesToString([]byte(vlan.Name))
					}
				}

				if len(lldp8201Q.PPVIDs) != 0 {
					portLLDPMetadata.PPVIDs = make([]PPVIDMetadata, len(lldp8201Q.PPVIDs))
					for i, ppvid := range lldp8201Q.PPVIDs {
						portLLDPMetadata.PPVIDs[i].Enabled = ppvid.Enabled
						portLLDPMetadata.PPVIDs[i].ID = int64(ppvid.ID)
						portLLDPMetadata.PPVIDs[i].Supported = ppvid.Supported
					}
				}
			}

			if lldp8023, err := lldpLayerInfo.Decode8023(); err == nil {
				if lldp8023.MTU != 0 {
					portMetadata["MTU"] = int64(lldp8023.MTU)
				}
			}
		}

		p.Ctx.Graph.Lock()

		// Create a node for the sending chassis with a predictable ID
		// Some switches - such as Cisco Nexus - sends a different chassis ID
		// for each port, so you use SysName and MgmtAddress if present and
		// fallback to chassis ID otherwise.
		if len(chassisDiscriminators) == 0 {
			chassisDiscriminators = append(chassisDiscriminators, chassisID, lldpLayer.ChassisID.Subtype.String())
		}

		chassisNodeID := graph.GenID(chassisDiscriminators...)
		chassis := p.getOrCreate(chassisNodeID, chassisMetadata)

		// Delete nodes with the same mgmt address
		// Reason: MgmtAddress must be unique between switches
		if mgmtAddress, _ := chassisMetadata.GetFieldString("LLDP.MgmtAddress"); len(mgmtAddress) > 0 {
			dupSwitches := p.Ctx.Graph.GetNodes(graph.Metadata{"LLDP.MgmtAddress": mgmtAddress})
			for _, sw := range dupSwitches {
				if sw != chassis {
					for _, pt := range p.Ctx.Graph.LookupChildren(sw, nil, topology.OwnershipMetadata()) {
						p.Ctx.Graph.DelNode(pt)
					}
					p.Ctx.Graph.DelNode(sw)
				}
			}
		}

		// Create a port with a predicatable ID
		port := p.getOrCreate(graph.GenID(
			string(chassisNodeID),
			portID, lldpLayer.PortID.Subtype.String(),
		), portMetadata)

		if !topology.HaveOwnershipLink(p.Ctx.Graph, chassis, port) {
			topology.AddOwnershipLink(p.Ctx.Graph, chassis, port, nil)
		}

		var err error
		link := p.Ctx.Graph.GetFirstLink(port, n, topology.Layer2Metadata())
		if link == nil {
			link, err = topology.AddLayer2Link(p.Ctx.Graph, port, n, nil)
		}
		if err == nil {
			p.linkWatcher.Update(link.ID)
			p.Ctx.Graph.AddMetadata(link, "State", LinkActive)
		}

		p.Ctx.Graph.Unlock()
	}
}

func (p *Probe) startCapture(ifName, mac string, n *graph.Node) error {
	lldpPrefix := "01:80:c2:00:00"
	for _, lastByte := range []byte{0x00, 0x03, 0x0e} {
		// Add multicast address so that the kernel does not discard it
		if err := addMulticastAddr(ifName, fmt.Sprintf("%s:%02X", lldpPrefix, lastByte)); err != nil {
			return fmt.Errorf("Failed to add multicast address: %s", err)
		}
	}

	// Set BPF filter to only capture LLDP packets
	bpfFilter := fmt.Sprintf(lldpBPFFilter, mac)

	ctx := probes.Context{
		Config: p.Ctx.Config,
		Logger: p.Ctx.Logger,
		Graph:  p.Ctx.Graph,
	}

	packetProbe, err := gp.NewCapture(ctx, n, gp.AFPacket, bpfFilter, lldpSnapLen)
	if err != nil {
		return err
	}

	// Set capturing state to true
	p.interfaceMap[ifName] = packetProbe

	p.wg.Add(1)

	go func() {
		defer func() {
			p.Ctx.Logger.Infof("Stopping LLDP capture on %s", ifName)

			p.Lock()
			p.interfaceMap[ifName] = nil
			p.Unlock()

			p.wg.Done()
		}()

		err := packetProbe.Run(
			func(packet gopacket.Packet) {
				p.handlePacket(n, ifName, packet)
			},
			func(stats flow.Stats) {
			},
			&lldpCapture{})

		if err != nil {
			p.Ctx.Logger.Errorf("LLDP capture error on %s", ifName)
		}
	}()

	return err
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
		// Do not change chassisID
		if cid, err := node.GetFieldString("LLDP.ChassisID"); err != nil {
			m.SetField("LLDP.ChassisID", cid)
		}
		tr := p.Ctx.Graph.StartMetadataTransaction(node)
		for k, v := range m {
			tr.AddMetadata(k, v)
		}
		tr.Commit()
	}
	return node
}

// handleNode checks if LLDP capture should be started on the passed interface node, ie:
// - when no LLDP capture is running for this interface
// - when its first packet layer is Ethernet and it has a MAC address
// - when the interface is listed in the configuration file or we are in auto discovery mode
func (p *Probe) handleNode(n *graph.Node) {
	if state, _ := n.GetFieldString("State"); state != "UP" {
		return
	}

	firstLayerType, _ := gp.FirstLayerType(n)
	mac, _ := n.GetFieldString("BondSlave.PermMAC")
	if mac == "" {
		mac, _ = n.GetFieldString("MAC")
	}
	name, _ := n.GetFieldString("Name")

	if name != "" && mac != "" && firstLayerType == layers.LayerTypeEthernet {
		if activeProbe, found := p.interfaceMap[name]; (found || p.autoDiscovery) && activeProbe == nil {
			p.Ctx.Logger.Infof("Starting LLDP capture on %s (MAC: %s)", name, mac)
			if err := p.startCapture(name, mac, n); err != nil {
				p.Ctx.Logger.Error(err)
			}
		}
	}
}

// OnEdgeAdded is called when a new edge was created on the graph
func (p *Probe) OnEdgeAdded(e *graph.Edge) {
	p.Lock()
	defer p.Unlock()

	// Only consider nodes that are owned by the host node
	if e.Parent == p.Ctx.RootNode.ID {
		if relationType, _ := e.GetFieldString("RelationType"); relationType == topology.OwnershipLink {
			n := p.Ctx.Graph.GetNode(e.Child)
			p.handleNode(n)
		}
	}
}

// OnNodeUpdated is called when a new node was updated on the graph
func (p *Probe) OnNodeUpdated(n *graph.Node) {
	p.Lock()
	defer p.Unlock()

	if p.Ctx.Graph.AreLinked(p.Ctx.RootNode, n, topology.OwnershipMetadata()) {
		p.handleNode(n)
	}
}

// Start capturing LLDP packets
func (p *Probe) Start() error {
	if !p.state.CompareAndSwap(service.StoppedState, service.RunningState) {
		return probe.ErrNotStopped
	}

	p.Ctx.Graph.AddEventListener(p)

	p.Ctx.Graph.RLock()
	defer p.Ctx.Graph.RUnlock()
	p.Lock()
	defer p.Unlock()

	p.wg.Add(1)
	p.linkWatcher.Watch(&p.wg, func(id graph.Identifier) {
		p.linkWatcher.Drop(id)
		if link := p.Ctx.Graph.GetEdge(id); link != nil {
			p.Ctx.Graph.Lock()
			p.Ctx.Graph.AddMetadata(link, "State", LinkInactive)
			p.Ctx.Graph.Unlock()
		}
	})

	// The nodes may have already been created
	children := p.Ctx.Graph.LookupChildren(p.Ctx.RootNode, nil, topology.OwnershipMetadata())
	for _, intfNode := range children {
		p.handleNode(intfNode)
	}

	return nil
}

// Stop capturing LLDP packets
func (p *Probe) Stop() {
	p.Ctx.Graph.RemoveEventListener(p)
	p.linkWatcher.Stop()
	p.state.Store(service.StoppingState)
	for intf, activeProbe := range p.interfaceMap {
		if activeProbe != nil {
			p.Ctx.Logger.Debugf("Stopping probe on %s", intf)
			activeProbe.Stop()
		}
	}
	p.wg.Wait()
}

// NewProbe creates a new LLDP probe
func NewProbe(ctx tp.Context, bundle *probe.Bundle) (probe.Handler, error) {
	var (
		interfaces  = ctx.Config.GetStringSlice("agent.topology.lldp.interfaces")
		timeoutStr  = ctx.Config.GetString("agent.topology.lldp.timeout")
		intervalStr = ctx.Config.GetString("agent.topology.lldp.interval")
		watcher     = &Watcher{elements: make(map[graph.Identifier]time.Time), quit: make(chan bool)}
	)
	interfaceMap := make(map[string]*gp.Probe)
	for _, intf := range interfaces {
		interfaceMap[intf] = nil
	}

	if timeout, err := time.ParseDuration(timeoutStr); err == nil {
		watcher.timeout = timeout
	} else {
		watcher.timeout = 5 * time.Minute
	}

	if interval, err := time.ParseDuration(intervalStr); err == nil {
		watcher.interval = interval
	} else {
		watcher.interval = 10 * time.Minute
	}

	return &Probe{
		Ctx:           ctx,
		interfaceMap:  interfaceMap,
		state:         service.StoppedState,
		autoDiscovery: len(interfaces) == 0,
		linkWatcher:   watcher,
	}, nil
}

// Register registers graph metadata decoders
func Register() {
	graph.NodeMetadataDecoders["LLDP"] = MetadataDecoder
}
