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
	"github.com/skydive-project/skydive/rbac"
)

// NotImplementedError deals with unexpected data while parsing contrail introspect data
type NotImplementedError struct {
	errString string
}

func (e NotImplementedError) Error() string {
	return e.errString
}

// TungstenFabricAPI exposes TungstenFabric query API
type TungstenFabricAPI struct {
	graph *graph.Graph
}

// NH contains next hop information
type NH struct {
	Type      string
	Interface string
	SrcIP     string
	DestIP    string
	TunType   string
	Label     string
	VNI       string
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

func lookupVrfNH(vrIP, vrfName, path string) (nh *NH, err error) {
	// Load Route collection from vrouter's introspect API
	col, _ := collection.LoadCollection(
		descriptions.Route(),
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
	routeType, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/type")
	sourceIP, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/sip")
	destIP, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/dip")
	itf, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/itf")
	tunType, _ := matched.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/tunnel_type")
	label, _ := matched.GetField("path_list/list/PathSandeshData[1]/label")
	vni, _ := matched.GetField("path_list/list/PathSandeshData[1]/vxlan_id")

	nh = &NH{
		Type:      routeType,
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
	routeType, _ := elem.GetField("nh/NhSandeshData/type")
	sourceIP, _ := elem.GetField("nh/NhSandeshData/sip")
	destIP, _ := elem.GetField("nh/NhSandeshData/dip")
	itf, _ := elem.GetField("nh/NhSandeshData/itf")
	tunType, _ := elem.GetField("nh/NhSandeshData/tunnel_type")
	return &NH{
		Type:      routeType,
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
	routeType, _ := elem.GetField("nh/NhSandeshData/type")
	sourceIP, _ := elem.GetField("nh/NhSandeshData/sip")
	destIP, _ := elem.GetField("nh/NhSandeshData/dip")
	itf, _ := elem.GetField("nh/NhSandeshData/itf")
	tunType, _ := elem.GetField("nh/NhSandeshData/tunnel_type")
	return &NH{
		Type:      routeType,
		Interface: itf,
		SrcIP:     sourceIP,
		DestIP:    destIP,
		TunType:   tunType,
		Label:     label,
	}, nil
}

func newEdge(g *graph.Graph, parent, child *graph.Node, m graph.Metadata) *graph.Edge {
	m["Type"] = "overlay-flow"
	e, _ := g.NewEdge(graph.GenID(string(parent.ID), string(child.ID), "flow-edge"), parent, child, m)
	return e
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

func tracePath(g *graph.Graph, srcIP, destIP string) ([]*graph.Edge, error) {
	g.RLock()
	defer g.RUnlock()
	var edges []*graph.Edge
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
	edges = append(edges, newEdge(g, srcVM, srcTap, graph.Metadata{"Description": "vm-to-tap"}))

	vhost := g.LookupFirstChild(srcTap, graph.Metadata{"Type": "vhost"})
	if vhost == nil {
		tapName, _ := srcTap.GetFieldString("Name")
		return nil, fmt.Errorf("vhost interface for tap %s not found", tapName)
	}
	vrIPs, err := vhost.GetFieldStringList("IPV4")
	if err != nil {
		return nil, err
	}
	vrfName, err := srcTap.GetFieldString("Contrail.VRF")
	if err != nil {
		return nil, err
	}
	nh, _ := lookupVrfNH(strings.Split(vrIPs[0], "/")[0], vrfName, destIP)
	for node := srcTap; node != destTap; {
		if nh == nil {
			return nil, nil
		}
		switch {
		case nh.Type == "interface":
			// "interface" type indicates that nh is the destTap interface
			var m graph.Metadata
			if nodeType, _ := node.GetFieldString("Type"); nodeType == "vhost" {
				m = edges[len(edges)-1].Metadata
			} else {
				m = graph.Metadata{"Description": "tap-to-tap"}
			}
			edges = append(edges, newEdge(g, node, destTap, m))
			node = destTap
		case nh.Type == "tunnel":
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
				nh, _ = lookupVxlanNH(nh.DestIP, nh.VNI)
				if err != nil {
					return nil, err
				}
			} else {
				m["Label"] = nh.Label
				nh, _ = lookupMplsNH(nh.DestIP, nh.Label)
				if err != nil {
					return nil, err
				}
			}
			edges = append(
				edges,
				newEdge(g, node, vhost, m),
				newEdge(g, vhost, host, m),
				newEdge(g, host, nextHost, m),
				newEdge(g, nextHost, nextVhost, m),
			)
			node = nextVhost
		case nh.Type == "discard":
			return nil, nil
		default:
			// There's a indirect route from source to destination IP
			edges = []*graph.Edge{
				edges[0],
				newEdge(g, srcTap, destTap, graph.Metadata{"Description": "unknown"}),
			}
			node = destTap
		}
	}
	edges = append(edges, newEdge(g, destTap, destVM, graph.Metadata{"Description": "tap-to-vm"}))
	return edges, nil
}

func (tf *TungstenFabricAPI) pathTracingHandler(w http.ResponseWriter, r *auth.AuthenticatedRequest) {
	if !rbac.Enforce(r.Username, "topology", "read") {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	values := r.URL.Query()
	if len(values["src-ip"]) != 1 || len(values["dest-ip"]) != 1 {
		return
	}
	srcIP, destIP := values["src-ip"][0], values["dest-ip"][0]
	edges, err := tracePath(tf.graph, srcIP, destIP)
	if err != nil {
		logging.GetLogger().Error(err)
	}
	// Bypass the marshalling nil slices behaviour
	if len(edges) == 0 {
		edges = make([]*graph.Edge, 0)
	}
	je, _ := json.Marshal(edges)
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
