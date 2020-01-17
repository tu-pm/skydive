// +build linux

package opencontrail

import (
	"fmt"
	"time"

	"github.com/nlewo/contrail-introspect-cli/collection"
	"github.com/nlewo/contrail-introspect-cli/descriptions"
	"github.com/skydive-project/skydive/graffiti/graph"
)

func (p *Probe) getNexthopsFromIntrospect(host string, port int, vrfName string) (nhs []*NHTunnel) {
	col, err := collection.LoadCollection(
		descriptions.Route(),
		[]string{fmt.Sprintf("%s:%d", host, port), vrfName},
	)
	if err != nil {
		p.Ctx.Logger.Errorf("Error loading collection:")
		return
	}
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
		nh := &NHTunnel{
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
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var tunnels []*NHTunnel
			vrfs := make(map[string]struct{})
			p.RLock()
			for vrf := range p.vrfs {
				vrfs[vrf] = struct{}{}
			}
			p.RUnlock()
			for vrf := range p.vrfs {
				nhs := p.getNexthopsFromIntrospect(p.agentHost, p.agentPort, vrf)
				tunnels = append(tunnels, nhs...)
			}
			p.Ctx.Graph.Lock()
			vhost := p.Ctx.Graph.LookupFirstNode(graph.Metadata{"Type": "vhost"})
			if vhost == nil {
				continue
			}
			p.Ctx.Graph.AddMetadata(vhost, "Tunnels", tunnels)
			p.Ctx.Graph.Unlock()
		case <-p.quit:
			return
		}
	}
}
