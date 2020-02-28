// +build linux

package opencontrail

import (
	"fmt"
	"time"

	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/tu-pm/contrail-introspect-cli/collection"
	"github.com/tu-pm/contrail-introspect-cli/descriptions"
)

func getNexthopsFromIntrospect(host string, port int, vrfName string) (nhs []NHTunnel, err error) {
	col, err := collection.LoadCollection(
		descriptions.UcRoute(),
		[]string{fmt.Sprintf("%s:%d", host, port), vrfName},
	)
	if err != nil {
		return
	}
	defer col.Close()
	elems := col.Search(func(string, string) string {
		return "__Inet4UcRouteResp_list/Inet4UcRouteResp/route_list/list/RouteUcSandeshData"
	}, "", "")

	for _, elem := range elems {
		routeType, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/type")
		if routeType != "tunnel" {
			continue
		}
		prefixAddress, _ := elem.GetField("src_ip")
		prefixLen, _ := elem.GetField("src_plen")
		sourceIP, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/sip")
		destIP, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/dip")
		tunType, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/tunnel_type")
		valid, _ := elem.GetField("path_list/list/PathSandeshData[1]/nh/NhSandeshData/valid")
		nh := NHTunnel{
			VrfName:       vrfName,
			Prefix:        fmt.Sprintf("%s/%s", prefixAddress, prefixLen),
			SourceIP:      sourceIP,
			DestinationIP: destIP,
			TunnelType:    tunType,
			Valid:         valid == "true",
		}
		nhs = append(nhs, nh)
	}
	return
}

func (p *Probe) tunnelUpdater() {
	var (
		vrfs    []string
		tunnels []NHTunnel
	)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Get a copy of current vrfs on vrouter
			p.RLock()
			for vrf := range p.vrfs {
				vrfs = append(vrfs, vrf)
			}
			p.Ctx.Logger.Debugf("VRF list: %v", vrfs)
			p.RUnlock()

			// Fetching NHs tunnel correspond to each vrf
			// This is a time-consuming operation that can be executed concurrently if needed.
			for _, vrf := range vrfs {
				nhs, _ := getNexthopsFromIntrospect(p.agentHost, p.agentPort, vrf)
				tunnels = append(tunnels, nhs...)
			}

			// Add tunnels to vhost metadata
			p.Ctx.Graph.Lock()
			vhost := p.Ctx.Graph.LookupFirstNode(graph.Metadata{"Type": "vhost"})
			if vhost == nil {
				continue
			}
			p.Ctx.Graph.AddMetadata(vhost, "Tunnels", tunnels)
			p.Ctx.Graph.Unlock()

			// Free up memory
			vrfs = nil
			tunnels = nil
		case <-p.quit:
			return
		}
	}
}
