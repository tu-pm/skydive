package server

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/skydive-project/skydive/logging"
	"github.com/skydive-project/skydive/rbac"
	"github.com/skydive-project/skydive/topology"
	"github.com/tu-pm/contrail-introspect-cli/collection"
	"github.com/tu-pm/contrail-introspect-cli/descriptions"

	auth "github.com/abbot/go-http-auth"
	"github.com/skydive-project/skydive/graffiti/graph"
	shttp "github.com/skydive-project/skydive/http"
)

// TungstenFabricAPI exposes TungstenFabric query API
type TungstenFabricAPI struct {
	graph *graph.Graph
}

// NH contains next hop information
type NH struct {
	VrouterIP string
	Type      string
	Vrf       string
	Interface string
	SrcIP     string
	DestIP    string
	TunType   string
	Label     string
	VNI       string
}

// Link describes a link between two graph node on the path
type Link struct {
	Parent   string
	Child    string
	Metadata graph.Metadata
}

// Path represents a path between two nodes
type Path struct {
	links []Link
	err   error
}

func (p *Path) connect(node1, node2 *graph.Node, metadata graph.Metadata) {
	if node1 == nil || node2 == nil || node1.ID == node2.ID {
		return
	}
	metadata["Type"] = "overlay-flow"
	link := Link{
		Parent:   string(node1.ID),
		Child:    string(node2.ID),
		Metadata: metadata,
	}
	p.links = append(p.links, link)
}

type chassis struct {
	node  *graph.Node
	ports []*graph.Node
}

func vhostToSwitch(g *graph.Graph, vhost *graph.Node) (sw chassis) {
	// Get link from vhost to its parent interface
	link := topology.GetFirstEdge(g, vhost, graph.Metadata{"Tag": "vhost-to-parent"})
	if link == nil {
		return
	}
	// Get vhost's parent interface
	parent := topology.GetPeer(g, vhost, link, nil)
	// If parent is vlan interface, get its physical interface
	link = topology.GetFirstEdge(g, parent, graph.Metadata{"Type": "vlan"})
	if link != nil {
		parent = topology.GetPeer(g, vhost, link, nil)
	}
	var ifaces []*graph.Node
	if driver, _ := parent.GetFieldString("Driver"); driver == "bonding" {
		for _, link := range g.GetNodeEdges(parent, topology.Layer2Metadata()) {
			if iface := topology.GetPeer(g, parent, link, nil); iface != nil {
				ifaces = append(ifaces, iface)
			}
		}

	} else {
		ifaces = append(ifaces, parent)
	}
	// Get switch's ports corresponding to host's interfaces
	for _, itf := range ifaces {
		var swPort *graph.Node
		for _, link = range g.GetNodeEdges(itf, topology.Layer2Metadata()) {
			if swPort = topology.GetPeer(g, itf, link, graph.Metadata{"Type": "switchport"}); swPort != nil {
				break
			}
		}
		if swPort != nil {
			sw.ports = append(sw.ports, swPort)
			if sw.node == nil {
				sw.node = g.LookupParents(swPort, graph.Metadata{"Type": "switch"}, topology.OwnershipMetadata())[0]
			}
		}
	}
	return
}

func connectVhosts(p *Path, g *graph.Graph, srcVhost, destVhost *graph.Node, metadata graph.Metadata) {
	var (
		srcHost    = g.LookupParents(srcVhost, nil, topology.OwnershipMetadata())[0]
		destHost   = g.LookupParents(destVhost, nil, topology.OwnershipMetadata())[0]
		srcSwitch  = vhostToSwitch(g, srcVhost)
		destSwitch = vhostToSwitch(g, destVhost)
	)

	p.connect(srcVhost, srcHost, metadata)
	defer p.connect(destHost, destVhost, metadata)

	// If srcSwitch or destSwitch does not exist, just connect two hosts without drawing a path through intermediate switches
	if srcSwitch.node == nil || destSwitch.node == nil {
		p.connect(srcHost, destHost, metadata)
		return
	}

	// for _, port := range srcSwitch.ports {
	// 	p.connect(srcHost, port, metadata)
	// }
	p.connect(srcHost, srcSwitch.node, metadata)

	// Connect underlay topology
	if srcSwitch.node.ID != destSwitch.node.ID {
		// p.connectSwitches(g, srcSwitch.node, destSwitch.node, "", "")
		p.connect(srcSwitch.node, destSwitch.node, metadata)
	}

	// for _, port := range destSwitch.ports {
	// 	p.connect(port, destHost, metadata)
	// }
	p.connect(destSwitch.node, destHost, metadata)
}

func (p *Path) connectSwitches(g *graph.Graph, srcSw, destSw *graph.Node, srcAddr, destAddr string) {
	// TODO: Find an active flow between two addresses travelling through srcSw and destSw
	return
}

func compareIP(x, y string, mask int) (cpl int, err error) {
	ipx := net.ParseIP(x)
	if ipx == nil {
		return -1, fmt.Errorf("invalid lookup address: %s", x)
	}
	ipy := net.ParseIP(y)
	if ipy == nil {
		return -1, fmt.Errorf("invalid lookup address: %s", y)
	}
	for i := 12; i < 16; i++ {
		common := bits.LeadingZeros8(ipx[i] ^ ipy[i])
		cpl += common
		if common != 8 {
			break
		}
	}
	if cpl < mask {
		return -1, nil
	}
	return cpl, nil
}

func lookupL2NH(vrIP, vrfName, mac string) (nh *NH, err error) {
	// Load Route collection from vrouter's introspect API
	col, _ := collection.LoadCollection(
		descriptions.L2Route(),
		[]string{fmt.Sprintf("%s:%d", vrIP, 8085), vrfName},
	)
	defer col.Close()

	elem, err := col.SearchStrictUnique(mac)
	if err != nil {
		return nil, err
	}
	var (
		nhType, _   = elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/type")
		vrf, _      = elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/vrf")
		sourceIP, _ = elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/sip")
		destIP, _   = elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/dip")
		itf, _      = elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/itf")
		tunType, _  = elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/tunnel_type")
		label, _    = elem.GetField("path_list/list/PathSandeshData[1]/label")
		vni, _      = elem.GetField("path_list/list/PathSandeshData[1]/vxlan_id")
	)

	nh = &NH{
		VrouterIP: vrIP,
		Type:      nhType,
		Vrf:       vrf,
		Interface: itf,
		SrcIP:     sourceIP,
		DestIP:    destIP,
		TunType:   tunType,
		Label:     label,
		VNI:       vni,
	}
	return
}

func lookupUcNH(vrIP, vrfName, ip string) (*NH, error) {
	// Load Route collection from vrouter's introspect API
	col, _ := collection.LoadCollection(
		descriptions.UcRoute(),
		[]string{fmt.Sprintf("%s:%d", vrIP, 8085), vrfName},
	)
	defer col.Close()

	// Search for RouteUcSandeshData elements
	elems := col.Search(func(string, string) string {
		return "__Inet4UcRouteResp_list/Inet4UcRouteResp/route_list/list/RouteUcSandeshData"
	}, "", "")

	// Get the longest matching entry in routing table
	var (
		matchElem collection.Element
		maxLen    = -1
	)
	for _, elem := range elems {
		var (
			srcIP, _    = elem.GetField("src_ip")
			srcPlen, _  = elem.GetField("src_plen")
			prefLen, _  = strconv.Atoi(srcPlen)
			matchLen, _ = compareIP(ip, srcIP, prefLen)
		)
		if matchLen > maxLen {
			maxLen = matchLen
			matchElem = elem
		}
	}
	if maxLen == -1 {
		return nil, fmt.Errorf("Route not found, vrouter: %s, vrf: %s, lookup: %s", vrIP, vrfName, ip)
	}
	var (
		nhType, _   = matchElem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/type")
		vrf, _      = matchElem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/vrf")
		sourceIP, _ = matchElem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/sip")
		destIP, _   = matchElem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/dip")
		itf, _      = matchElem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/itf")
		tunType, _  = matchElem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/tunnel_type")
		label, _    = matchElem.GetField("path_list/list/PathSandeshData[1]/label")
		vni, _      = matchElem.GetField("path_list/list/PathSandeshData[1]/vxlan_id")
	)

	return &NH{
		VrouterIP: vrIP,
		Type:      nhType,
		Vrf:       vrf,
		Interface: itf,
		SrcIP:     sourceIP,
		DestIP:    destIP,
		TunType:   tunType,
		Label:     label,
		VNI:       vni,
	}, nil
}

func lookupVxlanNH(vrIP string, vxlanID string) (*NH, error) {
	col, _ := collection.LoadCollection(
		descriptions.Vxlan(),
		[]string{fmt.Sprintf("%s:%d", vrIP, 8085)},
	)
	defer col.Close()
	elem, err := col.SearchStrictUnique(vxlanID)
	if err != nil {
		return nil, fmt.Errorf("Route not found, vrouter: %s, vxlanID: %s", vrIP, vxlanID)
	}
	var (
		nhType, _   = elem.GetField("nh/NhSandeshData/type")
		vrf, _      = elem.GetField("nh/NhSandeshData/vrf")
		sourceIP, _ = elem.GetField("nh/NhSandeshData/sip")
		destIP, _   = elem.GetField("nh/NhSandeshData/dip")
		itf, _      = elem.GetField("nh/NhSandeshData/itf")
		tunType, _  = elem.GetField("nh/NhSandeshData/tunnel_type")
	)
	return &NH{
		VrouterIP: vrIP,
		Type:      nhType,
		Vrf:       vrf,
		Interface: itf,
		SrcIP:     sourceIP,
		DestIP:    destIP,
		TunType:   tunType,
		VNI:       vxlanID,
	}, nil
}

func lookupMplsNH(vrIP string, label string) (*NH, error) {
	col, _ := collection.LoadCollection(
		descriptions.Mpls(),
		[]string{fmt.Sprintf("%s:%d", vrIP, 8085)},
	)
	defer col.Close()
	elem, err := col.SearchStrictUnique(label)
	if err != nil {
		return nil, fmt.Errorf("Route not found, vrouter: %s, mpls label: %s", vrIP, label)
	}
	var (
		nhType, _   = elem.GetField("nh/NhSandeshData/type")
		vrf, _      = elem.GetField("nh/NhSandeshData/vrf")
		sourceIP, _ = elem.GetField("nh/NhSandeshData/sip")
		destIP, _   = elem.GetField("nh/NhSandeshData/dip")
		itf, _      = elem.GetField("nh/NhSandeshData/itf")
		tunType, _  = elem.GetField("nh/NhSandeshData/tunnel_type")
	)
	return &NH{
		VrouterIP: vrIP,
		Type:      nhType,
		Vrf:       vrf,
		Interface: itf,
		SrcIP:     sourceIP,
		DestIP:    destIP,
		TunType:   tunType,
		Label:     label,
	}, nil
}

func getTapFromIP(g *graph.Graph, ip string) (tap *graph.Node) {
	for _, node := range g.GetNodes(graph.Metadata{"Type": "tun"}) {
		cidrs, _ := node.GetFieldStringList("Neutron.IPV4")
		for _, cidr := range cidrs {
			tapIP := strings.Split(cidr, "/")[0]
			if ip == tapIP {
				return node
			}
		}
	}
	return nil
}

func getVhostFromIP(g *graph.Graph, ip string) (vhost *graph.Node) {
	for _, node := range g.GetNodes(graph.Metadata{"Type": "vhost"}) {
		cidrs, _ := node.GetFieldStringList("IPV4")
		for _, cidr := range cidrs {
			vhostIP := strings.Split(cidr, "/")[0]
			if ip == vhostIP {
				return node
			}
		}
	}
	return nil
}

func connectTaps(g *graph.Graph, srcTap, destTap *graph.Node, destIP string) (flowType string, nh *NH, err error) {
	// Extract src vrouter IP
	vhost := g.LookupFirstChild(srcTap, graph.Metadata{"Type": "vhost"})
	if vhost == nil {
		tapName, _ := srcTap.GetFieldString("Name")
		return "", nil, fmt.Errorf("vhost interface for tap %s not found", tapName)
	}
	vrIPs, err := vhost.GetFieldStringList("IPV4")
	if err != nil {
		return "", nil, err
	}
	// Determine what kind of table to lookup on from given addresses
	srcVrf, err := srcTap.GetFieldString("Contrail.VRF")
	if err != nil {
		return "", nil, err
	}
	destVrf, err := destTap.GetFieldString("Contrail.VRF")
	if err != nil {
		return "", nil, err
	}
	if srcVrf != destVrf {
		flowType = "L3"
		nh, err = lookupUcNH(strings.Split(vrIPs[0], "/")[0], srcVrf, destIP)
	} else {
		mac, _ := destTap.GetFieldString("Contrail.MAC")
		flowType = "L2"
		nh, err = lookupL2NH(strings.Split(vrIPs[0], "/")[0], srcVrf, mac)
	}
	return
}

func tracePath(g *graph.Graph, srcIP, destIP string) (path *Path) {
	path = &Path{links: make([]Link, 0), err: nil}
	// Get required nodes. If any of these nodes are missing,
	// the lookup operation should fail immediately
	srcTap := getTapFromIP(g, srcIP)
	if srcTap == nil {
		path.err = fmt.Errorf("tap interface with IP %s not found", srcIP)
		return
	}
	destTap := getTapFromIP(g, destIP)
	if destTap == nil {
		path.err = fmt.Errorf("tap interface with IP %s not found", destIP)
		return
	}
	// The first link is always from srcVM to srcTap
	srcVM := g.LookupFirstChild(srcTap, graph.Metadata{"Type": "libvirt"})
	path.connect(srcVM, srcTap, graph.Metadata{"Label": "vm-to-tap"})
	flowType, nh, err := connectTaps(g, srcTap, destTap, destIP)
	for node := srcTap; node != destTap; {
		if err != nil {
			path.err = err
			path.links = make([]Link, 0)
			return
		}
		switch {
		case nh.Type == "interface":
			// "interface" type indicates that nh is the destTap interface
			tapName, _ := destTap.GetFieldString("Name")
			logging.GetLogger().Debugf("Trace Path: Arrived at: %s\n", tapName)
			path.connect(node, destTap, graph.Metadata{"Label": "overlay"})
			node = destTap
		case nh.Type == "tunnel":
			// "tunnel" type indicates that nh is the vhost interface on another compute node
			logging.GetLogger().Debugf("Trace Path: Tunnel nh: %+v\n", nh)
			vhost := getVhostFromIP(g, nh.SrcIP)
			if vhost == nil {
				path.err = fmt.Errorf("vHost with IP %s not found", nh.SrcIP)
				return
			}
			nextVhost := getVhostFromIP(g, nh.DestIP)
			if nextVhost == nil {
				path.err = fmt.Errorf("vHost with IP %s not found", nh.DestIP)
				return
			}
			metadata := graph.Metadata{"Description": "overlay", "TunnelType": nh.TunType}
			if nh.TunType == "VXLAN" {
				metadata["VNI"] = nh.VNI
				nh, err = lookupVxlanNH(nh.DestIP, nh.VNI)
			} else {
				metadata["Label"] = nh.Label
				nh, err = lookupMplsNH(nh.DestIP, nh.Label)
			}
			path.connect(node, vhost, graph.Metadata{"Label": "overlay"})
			connectVhosts(path, g, vhost, nextVhost, metadata)
			node = nextVhost
		case nh.Type == "vrf":
			// "vrf" type indicates that we need to translate nh
			// when we are at a different compute node
			logging.GetLogger().Debugf("Trace Path: Vrf translate nh: %+v\n", nh)
			if flowType == "L3" {
				nh, err = lookupUcNH(nh.VrouterIP, nh.Vrf, destIP)
			} else {
				destMAC, _ := destTap.GetFieldString("Contrail.MAC")
				nh, err = lookupL2NH(nh.VrouterIP, nh.Vrf, destMAC)
			}
		case nh.Type == "discard":
			path.err = fmt.Errorf("connection is discarded by vrouter")
			return
		default:
			// There's a indirect route from source to destination IP (through service instances, for example)
			logging.GetLogger().Debugf("Trace Path: Unknown NH: %+v\n", nh)
			path.connect(srcTap, destTap, graph.Metadata{"Label": "unknown"})
			node = destTap
		}
	}
	destVM := g.LookupFirstChild(destTap, graph.Metadata{"Type": "libvirt"})
	path.connect(destTap, destVM, graph.Metadata{"Label": "tap-to-vm"})
	return
}

func (tf *TungstenFabricAPI) pathTracingHandler(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	if !rbac.Enforce(r.Username, "topology", "read") {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)

	r.ParseForm()
	var (
		srcIPForm  = r.Form["srcIP"]
		destIPForm = r.Form["destIP"]
		srcIP      string
		destIP     string
	)
	if len(srcIPForm) != 0 && len(destIPForm) != 0 {
		srcIP, destIP = srcIPForm[0], destIPForm[0]
	}
	path := tracePath(tf.graph, srcIP, destIP)
	if path.err != nil {
		logging.GetLogger().Error(path.err)
	}
	je, _ := json.Marshal(path.links)
	w.Write(je)
}

func (tf *TungstenFabricAPI) registerEndpoints(r *shttp.Server, authBackend shttp.AuthenticationBackend) {
	routes := []shttp.Route{
		{
			Name:        "TungstenFabricPathTracer",
			Method:      "POST",
			Path:        "/api/tungstenfabric",
			HandlerFunc: tf.pathTracingHandler,
		},
	}
	r.RegisterRoutes(routes, authBackend)
}

// RegisterTungstenFabricAPI registers a new TungstenFabric query API
func RegisterTungstenFabricAPI(r *shttp.Server, g *graph.Graph, authBackend shttp.AuthenticationBackend) {
	tf := &TungstenFabricAPI{graph: g}
	tf.registerEndpoints(r, authBackend)
}
