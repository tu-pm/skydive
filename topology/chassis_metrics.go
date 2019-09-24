//go:generate go run ../scripts/gendecoder.go -output chassis_metrics_gendecoder.go

package topology

import (
	json "encoding/json"

	"github.com/skydive-project/skydive/common"
)

// ChassisInterfaceMetric the interface packets counters
// easyjson:json
// gendecoder
type ChassisInterfaceMetric struct {
	IfInOctets         int64 `json:"IfInOctets,omitempty"`
	IfInUcastPkts      int64 `json:"IfInUcastPkts,omitempty"`
	IfInMulticastPkts  int64 `json:"IfInMulticastPkts,omitempty"`
	IfInBroadcastPkts  int64 `json:"IfInBroadcastPkts,omitempty"`
	IfInDiscards       int64 `json:"IfInDiscards,omitempty"`
	IfInErrors         int64 `json:"IfInErrors,omitempty"`
	IfInUnknownProtos  int64 `json:"IfInUnknownProtos,omitempty"`
	IfOutOctets        int64 `json:"IfOutOctets,omitempty"`
	IfOutUcastPkts     int64 `json:"IfOutUcastPkts,omitempty"`
	IfOutMulticastPkts int64 `json:"IfOutMulticastPkts,omitempty"`
	IfOutBroadcastPkts int64 `json:"IfOutBroadcastPkts,omitempty"`
	IfOutDiscards      int64 `json:"IfOutDiscards,omitempty"`
	IfOutErrors        int64 `json:"IfOutErrors,omitempty"`
	Start              int64 `json:"Start,omitempty"`
	Last               int64 `json:"Last,omitempty"`
}

// ChassisInterfaceMetricMetadataDecoder implements a json message raw decoder
func ChassisInterfaceMetricMetadataDecoder(raw json.RawMessage) (common.Getter, error) {
	var metric ChassisInterfaceMetric
	if err := json.Unmarshal(raw, &metric); err != nil {
		return nil, err
	}

	return &metric, nil
}

// GetStart returns start time
func (im *ChassisInterfaceMetric) GetStart() int64 {
	return im.Start
}

// SetStart set start time
func (im *ChassisInterfaceMetric) SetStart(start int64) {
	im.Start = start
}

// GetLast returns last time
func (im *ChassisInterfaceMetric) GetLast() int64 {
	return im.Last
}

// SetLast set last tome
func (im *ChassisInterfaceMetric) SetLast(last int64) {
	im.Last = last
}

// Add sum two metrics and return a new Metrics object
func (im *ChassisInterfaceMetric) Add(m common.Metric) common.Metric {
	om := m.(*ChassisInterfaceMetric)

	return &ChassisInterfaceMetric{
		IfInOctets:         im.IfInOctets + om.IfInOctets,
		IfInUcastPkts:      im.IfInUcastPkts + om.IfInUcastPkts,
		IfInMulticastPkts:  im.IfInMulticastPkts + om.IfInMulticastPkts,
		IfInBroadcastPkts:  im.IfInBroadcastPkts + om.IfInBroadcastPkts,
		IfInDiscards:       im.IfInDiscards + om.IfInDiscards,
		IfInErrors:         im.IfInErrors + om.IfInErrors,
		IfInUnknownProtos:  im.IfInUnknownProtos + om.IfInUnknownProtos,
		IfOutOctets:        im.IfOutOctets + om.IfOutOctets,
		IfOutUcastPkts:     im.IfOutUcastPkts + om.IfOutUcastPkts,
		IfOutMulticastPkts: im.IfOutMulticastPkts + om.IfOutMulticastPkts,
		IfOutBroadcastPkts: im.IfOutBroadcastPkts + om.IfOutBroadcastPkts,
		IfOutDiscards:      im.IfOutDiscards + om.IfOutDiscards,
		IfOutErrors:        im.IfOutErrors + om.IfOutErrors,
		Start:              im.Start,
		Last:               im.Last,
	}
}

// Sub subtracts two metrics and return a new metrics object
func (im *ChassisInterfaceMetric) Sub(m common.Metric) common.Metric {
	om := m.(*ChassisInterfaceMetric)

	return &ChassisInterfaceMetric{
		IfInOctets:         im.IfInOctets - om.IfInOctets,
		IfInUcastPkts:      im.IfInUcastPkts - om.IfInUcastPkts,
		IfInMulticastPkts:  im.IfInMulticastPkts - om.IfInMulticastPkts,
		IfInBroadcastPkts:  im.IfInBroadcastPkts - om.IfInBroadcastPkts,
		IfInDiscards:       im.IfInDiscards - om.IfInDiscards,
		IfInErrors:         im.IfInErrors - om.IfInErrors,
		IfInUnknownProtos:  im.IfInUnknownProtos - om.IfInUnknownProtos,
		IfOutOctets:        im.IfOutOctets - om.IfOutOctets,
		IfOutUcastPkts:     im.IfOutUcastPkts - om.IfOutUcastPkts,
		IfOutMulticastPkts: im.IfOutMulticastPkts - om.IfOutMulticastPkts,
		IfOutBroadcastPkts: im.IfOutBroadcastPkts - om.IfOutBroadcastPkts,
		IfOutDiscards:      im.IfOutDiscards - om.IfOutDiscards,
		IfOutErrors:        im.IfOutErrors - om.IfOutErrors,
		Start:              im.Start,
		Last:               im.Last,
	}
}

// IsZero returns true if all the values are equal to zero
func (im *ChassisInterfaceMetric) IsZero() bool {
	// sum as these numbers can't be <= 0
	return (im.IfInOctets +
		im.IfInUcastPkts +
		im.IfInMulticastPkts +
		im.IfInBroadcastPkts +
		im.IfInDiscards +
		im.IfInErrors +
		im.IfInUnknownProtos +
		im.IfOutOctets +
		im.IfOutUcastPkts +
		im.IfOutMulticastPkts +
		im.IfOutBroadcastPkts +
		im.IfOutDiscards +
		im.IfOutErrors) == 0
}

func (im *ChassisInterfaceMetric) applyRatio(ratio float64) *ChassisInterfaceMetric {
	return &ChassisInterfaceMetric{
		IfInOctets:         int64(float64(im.IfInOctets) * ratio),
		IfInUcastPkts:      int64(float64(im.IfInUcastPkts) * ratio),
		IfInMulticastPkts:  int64(float64(im.IfInMulticastPkts) * ratio),
		IfInBroadcastPkts:  int64(float64(im.IfInBroadcastPkts) * ratio),
		IfInDiscards:       int64(float64(im.IfInDiscards) * ratio),
		IfInErrors:         int64(float64(im.IfInErrors) * ratio),
		IfInUnknownProtos:  int64(float64(im.IfInUnknownProtos) * ratio),
		IfOutOctets:        int64(float64(im.IfOutOctets) * ratio),
		IfOutUcastPkts:     int64(float64(im.IfOutUcastPkts) * ratio),
		IfOutMulticastPkts: int64(float64(im.IfOutMulticastPkts) * ratio),
		IfOutBroadcastPkts: int64(float64(im.IfOutBroadcastPkts) * ratio),
		IfOutDiscards:      int64(float64(im.IfOutDiscards) * ratio),
		IfOutErrors:        int64(float64(im.IfOutErrors) * ratio),
		Start:              im.Start,
		Last:               im.Last,
	}
}

// Split splits a metric into two parts
func (im *ChassisInterfaceMetric) Split(cut int64) (common.Metric, common.Metric) {
	if cut <= im.Start {
		return nil, im
	} else if cut >= im.Last || im.Start == im.Last {
		return im, nil
	}

	duration := float64(im.Last - im.Start)

	ratio1 := float64(cut-im.Start) / duration
	ratio2 := float64(im.Last-cut) / duration

	m1 := im.applyRatio(ratio1)
	m1.Last = cut

	m2 := im.applyRatio(ratio2)
	m2.Start = cut

	return m1, m2
}
