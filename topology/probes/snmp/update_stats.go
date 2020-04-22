package snmp

import (
	"sync"
	"time"

	"github.com/skydive-project/skydive/common"
	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/logging"
	"github.com/skydive-project/skydive/topology"
	"github.com/soniah/gosnmp"
)

type ifResponse struct {
	address      string
	descriptions map[string]string
	configs      map[string]IfaceConfig
	metrics      map[string]*IfaceMetric
	err          error
}

func ifRequest(target, community string) *ifResponse {
	res := &ifResponse{
		address: target,
	}
	// Connect to target
	client := NewSnmpClient(target, community)
	err := client.Connect()
	if err != nil {
		res.err = err
		return res
	}
	defer client.Close()
	// Fetch configs and metrics of each port from IF-MIB
	var (
		portConfigs      = make(map[string]IfaceConfig)
		portMetrics      = make(map[string]*IfaceMetric)
		portDescriptions = make(map[string]string)
		metricOIDs       = IfMetricOIDs
		configOIDs       = IfConfigOIDs
		descrOID         = IfDescrOID
	)
	err = client.Walk(
		IfNameOID,
		func(pdu gosnmp.SnmpPDU) error {
			// Use port's name as key
			name, err := client.getPDUValue(pdu)
			if err != nil {
				return err
			}
			// Get port description
			nextDescrOID, descr, err := client.GetNext(descrOID)
			if err != nil {
				return err
			}
			portDescriptions[name.(string)] = descr.(string)
			// Get port configs
			config := make(IfaceConfig)
			nextConfigOIDs, err := client.GetNextMany(configOIDs, config)
			if err != nil {
				return err
			}
			portConfigs[name.(string)] = config
			// Get port metrics
			metric := &IfaceMetric{}
			nextMetricOIDs, err := client.GetNextMany(metricOIDs, metric)
			if err != nil {
				return err
			}
			metric.Set("Start", int64(0))
			metric.Set("Last", int64(0))
			portMetrics[name.(string)] = metric
			// Update OID strings
			configOIDs, metricOIDs, descrOID = nextConfigOIDs, nextMetricOIDs, nextDescrOID
			return nil
		},
	)
	if err != nil {
		res.err = err
		return res
	}
	res.descriptions = portDescriptions
	res.configs = portConfigs
	res.metrics = portMetrics
	return res
}

func genMetrics(port *graph.Node, metrics *IfaceMetric, now, last time.Time) graph.Metadata {
	newMetrics := &metrics.ChassisInterfaceMetric
	if newMetrics.IsZero() {
		return graph.Metadata{}
	}
	newMetrics.Last = int64(common.UnixMillis(now))

	currMetrics, err := port.GetField("ChassisIfMetric")
	if err != nil {
		currMetrics = &topology.ChassisInterfaceMetric{}
	}
	lastUpdateMetrics := newMetrics.Sub(
		currMetrics.(*topology.ChassisInterfaceMetric),
	).(*topology.ChassisInterfaceMetric)

	if lastUpdateMetrics.IsZero() {
		return graph.Metadata{}
	}
	lastUpdateMetrics.Start = int64(common.UnixMillis(last))
	lastUpdateMetrics.Last = int64(common.UnixMillis(now))
	return graph.Metadata{
		"ChassisIfMetric":           newMetrics,
		"LastUpdateChassisIfMetric": lastUpdateMetrics,
	}
}

func (p *Probe) portStatsUpdater(resp *ifResponse, now time.Time) {
	p.graph.Lock()
	defer p.graph.Unlock()
	if resp.err != nil {
		logging.GetLogger().Errorf("Failed to update stats at address %s: %v", resp.address, resp.err)
		return
	}
	swNode := p.graph.LookupFirstNode(graph.Metadata{"LLDP.MgmtAddress": resp.address, "Type": "switch"})
	if swNode == nil {
		return
	}
	portNodes := p.graph.LookupChildren(swNode, graph.Metadata{"Type": "switchport"}, nil)
	for _, portNode := range portNodes {
		var key string
		portName, _ := portNode.GetFieldString("Name")
		for name, descr := range resp.descriptions {
			if name == portName || descr == portName {
				key = name
				break
			}
		}
		if len(key) != 0 {
			p.updateMetadata(portNode, graph.Metadata(resp.configs[key]))
			p.updateMetadata(portNode, genMetrics(portNode, resp.metrics[key], now, p.lastUpdate))
		}
	}
}

func (p *Probe) updatePortStats() {
	var wg sync.WaitGroup
	ch := make(chan *ifResponse)
	go func() {
		now := time.Now().UTC()
		for resp := range ch {
			p.portStatsUpdater(resp, now)
		}
		p.lastUpdate = now
	}()
	for _, addr := range p.mgmtAddrs(true) {
		wg.Add(1)
		go func(target string, wg *sync.WaitGroup) {
			defer wg.Done()
			res := ifRequest(target, p.community)
			ch <- res
		}(addr, &wg)
	}
	wg.Wait()
	close(ch)
}
