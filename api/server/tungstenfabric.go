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

func getHostNode(g *graph.Graph, n *graph.Node) *graph.Node {
	return g.LookupParents(n, graph.Metadata{"Type": "host"}, topology.OwnershipMetadata())[0]
}

func commonPrefixLength(x, y string, mask int) (cpl int, err error) {
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
	nhType, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/type")
	vrf, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/vrf")
	sourceIP, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/sip")
	destIP, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/dip")
	itf, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/itf")
	tunType, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/tunnel_type")
	label, _ := elem.GetField("path_list/list/PathSandeshData[1]/label")
	vni, _ := elem.GetField("path_list/list/PathSandeshData[1]/vxlan_id")

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

func lookupUcNH(vrIP, vrfName, path string) (nh *NH, err error) {
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
	mlen := -1
	var matched collection.Element
	for _, elem := range elems {
		addr, _ := elem.GetField("src_ip")
		plenString, _ := elem.GetField("src_plen")
		plen, _ := strconv.Atoi(plenString)
		cpl, _ := commonPrefixLength(path, addr, plen)
		if cpl > mlen {
			mlen = cpl
			matched = elem
		}
		if cpl == 32 {
			break
		}
	}
	if mlen == -1 {
		return nil, fmt.Errorf("Route not found, vrouter: %s, vrf: %s, lookup: %s", vrIP, vrfName, path)
	}
	nhType, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/type")
	vrf, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/vrf")
	sourceIP, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/sip")
	destIP, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/dip")
	itf, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/itf")
	tunType, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/tunnel_type")
	label, _ := matched.GetField("path_list/list/PathSandeshData[1]/label")
	vni, _ := matched.GetField("path_list/list/PathSandeshData[1]/vxlan_id")

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
	nhType, _ := elem.GetField("nh/NhSandeshData/type")
	vrf, _ := elem.GetField("nh/NhSandeshData/vrf")
	sourceIP, _ := elem.GetField("nh/NhSandeshData/sip")
	destIP, _ := elem.GetField("nh/NhSandeshData/dip")
	itf, _ := elem.GetField("nh/NhSandeshData/itf")
	tunType, _ := elem.GetField("nh/NhSandeshData/tunnel_type")
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

func lookupMplsNH(vrIP string, label string) (nh *NH, err error) {
	col, _ := collection.LoadCollection(
		descriptions.Mpls(),
		[]string{fmt.Sprintf("%s:%d", vrIP, 8085)},
	)
	defer col.Close()
	elem, err := col.SearchStrictUnique(label)
	if err != nil {
		return nil, fmt.Errorf("Route not found, vrouter: %s, mpls label: %s", vrIP, label)
	}
	nhType, _ := elem.GetField("nh/NhSandeshData/type")
	vrf, _ := elem.GetField("nh/NhSandeshData/vrf")
	sourceIP, _ := elem.GetField("nh/NhSandeshData/sip")
	destIP, _ := elem.GetField("nh/NhSandeshData/dip")
	itf, _ := elem.GetField("nh/NhSandeshData/itf")
	tunType, _ := elem.GetField("nh/NhSandeshData/tunnel_type")
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
	logging.GetLogger().Infof("@@@ START: srcVrf: %s, destIP: %s\n", srcVrf, destIP)
	if srcVrf != destVrf {
		flowType = "L3"
		nh, err = lookupUcNH(strings.Split(vrIPs[0], "/")[0], srcVrf, destIP)
		logging.GetLogger().Infof("@@@: Diff net, search uc table => nh: %+v\n", nh)
	} else {
		flowType = "L2"
		mac, _ := destTap.GetFieldString("Contrail.MAC")
		nh, err = lookupL2NH(strings.Split(vrIPs[0], "/")[0], srcVrf, mac)
		logging.GetLogger().Infof("@@@: Same net, search l2 table => nh: %+v\n", nh)
	}
	return
}

func newLink(parent, child *graph.Node, m graph.Metadata) Link {
	m["Type"] = "overlay-flow"
	return Link{string(parent.ID), string(child.ID), m}
}

func ipToTap(g *graph.Graph, ip string) (tap *graph.Node) {
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

func ipToVhost(g *graph.Graph, ip string) (vhost *graph.Node) {
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

func tracePath(g *graph.Graph, srcIP, destIP string) ([]Link, error) {
	var links []Link
	// Get required nodes. If any of these nodes are missing,
	// the lookup operation should fail immediately
	srcTap := ipToTap(g, srcIP)
	if srcTap == nil {
		return nil, fmt.Errorf("Tap interface with IP %s not found", srcIP)
	}
	destTap := ipToTap(g, destIP)
	if destTap == nil {
		return nil, fmt.Errorf("Tap interface with IP %s not found", destIP)
	}
	srcVM := g.LookupFirstChild(srcTap, graph.Metadata{"Type": "libvirt"})
	if srcVM == nil {
		tapName, _ := srcTap.GetFieldString("Name")
		return nil, fmt.Errorf("VM attached to tap %s not found", tapName)
	}
	destVM := g.LookupFirstChild(destTap, graph.Metadata{"Type": "libvirt"})
	if destVM == nil {
		tapName, _ := destTap.GetFieldString("Name")
		return nil, fmt.Errorf("VM attached to tap %s not found", tapName)
	}
	// The first link is always from srcVM to srcTap
	links = append(links, newLink(srcVM, srcTap, graph.Metadata{"Description": "vm-to-tap"}))

	flowType, nh, err := connectTaps(g, srcTap, destTap, destIP)
	for node := srcTap; node != destTap; {
		if err != nil {
			return nil, err
		}
		switch {
		case nh.Type == "interface":
			tapName, _ := destTap.GetFieldString("Name")
			logging.GetLogger().Infof("@@@: END: Arrived at: %s\n", tapName)
			// "interface" type indicates that nh is the destTap interface
			var m graph.Metadata
			if nodeType, _ := node.GetFieldString("Type"); nodeType == "vhost" {
				m = links[len(links)-1].Metadata
			} else {
				m = graph.Metadata{"Description": "tap-to-tap"}
			}
			links = append(links, newLink(node, destTap, m))
			node = destTap
		case nh.Type == "tunnel":
			logging.GetLogger().Infof("@@@: ECAP TUNNEL: %+v\n", nh)
			// "tunnel" type indicates that nh is the vhost interface on another compute node
			vhost := ipToVhost(g, nh.SrcIP)
			if vhost == nil {
				return nil, fmt.Errorf("vHost with IP %s not found", nh.SrcIP)
			}
			host := getHostNode(g, vhost)
			nextVhost := ipToVhost(g, nh.DestIP)
			if nextVhost == nil {
				return nil, fmt.Errorf("vHost with IP %s not found", nh.DestIP)
			}
			nextHost := getHostNode(g, nextVhost)
			m := graph.Metadata{"Description": "overlay-tunnel", "TunnelType": nh.TunType}

			if nh.TunType == "VXLAN" {
				m["VNI"] = nh.VNI
				nh, err = lookupVxlanNH(nh.DestIP, nh.VNI)
			} else {
				m["Label"] = nh.Label
				nh, err = lookupMplsNH(nh.DestIP, nh.Label)
			}
			links = append(
				links,
				newLink(node, vhost, m),
				newLink(vhost, host, m),
				newLink(host, nextHost, m),
				newLink(nextHost, nextVhost, m),
			)
			node = nextVhost
		case nh.Type == "vrf":
			logging.GetLogger().Infof("@@@: VRF TRANSLATE: %+v\n", nh)
			if flowType == "L3" {
				nh, err = lookupUcNH(nh.VrouterIP, nh.Vrf, destIP)
			} else {
				destMAC, _ := destTap.GetFieldString("Contrail.MAC")
				nh, err = lookupL2NH(nh.VrouterIP, nh.Vrf, destMAC)
			}
		case nh.Type == "discard":
			return nil, nil
		default:
			// There's a indirect route from source to destination IP
			logging.GetLogger().Infof("@@@: Unknown NH: %+v\n", nh)
			links = []Link{
				links[0],
				newLink(srcTap, destTap, graph.Metadata{"Description": "unknown"}),
			}
			node = destTap
		}
	}
	links = append(links, newLink(destTap, destVM, graph.Metadata{"Description": "tap-to-vm"}))
	logging.GetLogger().Info("tupm: function result:", links)
	return links, nil
}

func (tf *TungstenFabricAPI) pathTracingHandler(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	// TODO: Add validator
	//

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	values := r.URL.Query()
	if len(values["src-ip"]) != 1 || len(values["dest-ip"]) != 1 {
		return
	}
	srcIP, destIP := values["src-ip"][0], values["dest-ip"][0]
	links, err := tracePath(tf.graph, srcIP, destIP)
	if err != nil {
		logging.GetLogger().Error(err)
	}
	// Bypass the marshalling nil slices behaviour
	if len(links) == 0 {
		links = make([]Link, 0)
	}
	je, _ := json.Marshal(links)
	w.Write(je)
}

func (tf *TungstenFabricAPI) registerEndpoints(r *shttp.Server, authBackend shttp.AuthenticationBackend) {
	routes := []shttp.Route{
		{
			Name:        "TungstenFabricPathTracer",
			Method:      "GET",
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
