package snmp

import (
	"context"
	"sync"
	"time"

	"github.com/skydive-project/skydive/logging"

	"github.com/skydive-project/skydive/graffiti/graph"
	"github.com/skydive-project/skydive/probe"
	"github.com/skydive-project/skydive/topology/probes"
)

// Probe implements the SNMP probe
type Probe struct {
	graph      *graph.Graph
	community  string
	lastUpdate time.Time
}

// Do implements main loop of the program
func (p *Probe) Do(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Add(1)
	go func() {
		logging.GetLogger().Debug("Discovering topology...")
		p.discoverFabricTopo()
		logging.GetLogger().Debug("Updating ports...")
		p.updatePortStats()
		wg.Done()
	}()
	return nil
}

// NewProbe initializes a new SNMP probe
func NewProbe(g *graph.Graph, community, interval string) (probe.Handler, error) {
	p := &Probe{
		graph:      g,
		community:  community,
		lastUpdate: time.Now().UTC(),
	}
	duration, err := time.ParseDuration(interval)
	if err != nil {
		return nil, err
	}
	return probes.NewProbeWrapperWithDuration(p, duration), nil
}
