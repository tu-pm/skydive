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
	address string
	configs map[string]*Payload
	metrics map[string]*Payload
	err     error
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
	portConfigs := make(map[string]*Payload)
	portMetrics := make(map[string]*Payload)
	metricOIDs, configOIDs := IfMetricOIDs, IfConfigOIDs
	err = client.Walk(
		IfNameOID,
		func(pdu gosnmp.SnmpPDU) error {
			// Use port's name as key
			name, err := client.getPDUValue(pdu)
			if err != nil {
				return err
			}
			// Get port configs
			nextConfigOIDs, config, err := client.GetNextMany(configOIDs)
			if err != nil {
				return err
			}
			portConfigs[name.(string)] = config
			// Get port metrics
			nextMetricOIDs, metric, err := client.GetNextMany(metricOIDs)
			if err != nil {
				return err
			}
			metric.SetValue("Start", int64(0))
			metric.SetValue("Last", int64(0))
			portMetrics[name.(string)] = metric
			// Update OID strings
			configOIDs, metricOIDs = nextConfigOIDs, nextMetricOIDs
			return nil
		},
	)
	if err != nil {
		res.err = err
		return res
	}
	res.configs = portConfigs
	res.metrics = portMetrics
	return res
}

func genMetrics(port *graph.Node, metrics *Payload, now, last time.Time) graph.Metadata {
	newMetrics := &topology.ChassisInterfaceMetric{}
	metrics.InitStruct(newMetrics)
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

func (p *Probe) portStatsUpdater(respChan <-chan *ifResponse) {
	now := time.Now().UTC()
	for resp := range respChan {
		if resp.err != nil {
			logging.GetLogger().Errorf("Failed to update stats at address %s: %v", resp.address, resp.err)
			continue
		}
		p.graph.Lock()
		swNode := p.graph.LookupFirstNode(graph.Metadata{"LLDP.MgmtAddress": resp.address, "Type": "switch"})
		if swNode == nil {
			p.graph.Unlock()
			continue
		}
		for _, portNode := range p.graph.LookupChildren(swNode, graph.Metadata{"Type": "switchport"}, nil) {
			portName, _ := portNode.GetFieldString("Name")
			// Update config
			configs, ok := resp.configs[portName]
			if !ok {
				p.graph.DelNode(portNode)
				continue
			}
			p.updateMetadata(portNode, graph.Metadata(*configs))
			// Update metrics
			metrics, _ := resp.metrics[portName]
			p.updateMetadata(portNode, genMetrics(portNode, metrics, now, p.lastUpdate))
		}
		p.graph.Unlock()
	}
	p.lastUpdate = now
}

func (p *Probe) updatePortStats() {
	var wg sync.WaitGroup
	ch := make(chan *ifResponse)
	go p.portStatsUpdater(ch)
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
