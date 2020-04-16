package snmp

import (
	"fmt"
	"reflect"

	"github.com/skydive-project/skydive/topology"
	"github.com/skydive-project/skydive/topology/probes/lldp"

	"github.com/google/gopacket/layers"
)

// Metadata represents information retrieved by using SNMP
type Metadata interface {
	Set(k string, v interface{}) error
}

// LLDPMetadata is information retrieved using SNMP requests on LLDP OIDs
type LLDPMetadata lldp.Metadata

// Set value on field
func (m *LLDPMetadata) Set(k string, v interface{}) error {
	if k == "ChassisIDType" {
		if val, ok := v.(int64); ok {
			v = (layers.LLDPChassisIDSubType(val)).String()
		} else {
			return fmt.Errorf("Invalid ChassisIDType %T", v)
		}
	} else if k == "PortIDType" {
		if val, ok := v.(int64); ok {
			v = (layers.LLDPPortIDSubType(val)).String()
		} else {
			return fmt.Errorf("Invalid PortIDType %T", v)
		}
	}
	return set(m, k, v)
}

// IfaceMetric are information retrieved using SNMP requests on IfMetricOIDs
type IfaceMetric struct {
	topology.ChassisInterfaceMetric
}

// Set value on field
func (m *IfaceMetric) Set(k string, v interface{}) error {
	return set(m, k, v)
}

// IfaceConfig is information retrived using SNMP requests on IfConfigOIDs
type IfaceConfig map[string]interface{}

// Set value on field
func (m IfaceConfig) Set(k string, v interface{}) error {
	if k == "State" {
		if val, ok := v.(int64); ok {
			v = stateMapping[byte(val)]
		} else {
			return fmt.Errorf("Invalid State %T", v)
		}
	}
	m[k] = v
	return nil
}

var stateMapping = map[byte]string{
	1: "UP",
	2: "DOWN",
	3: "TESTING",
	4: "UNKNOWN",
	5: "DORMANT",
	6: "NOTPRESENT",
	7: "LOWERLAYERDOWN",
}

// set value v on key k of struct obj
func set(obj interface{}, k string, v interface{}) error {
	var (
		properties = reflect.ValueOf(obj).Elem()
		field      = properties.FieldByName(k)
		val        = reflect.ValueOf(v)
	)
	if !field.IsValid() {
		return fmt.Errorf("Cannot set value %v for field %s: Field %s not found", v, k, k)
	}
	if !field.CanSet() {
		return fmt.Errorf("Cannot set value %v for field %s: Field %s is not settable", v, k, k)
	}
	if field.Type() != val.Type() {
		return fmt.Errorf(
			"Cannot set value %v for field %s: Type mismatch, type %s can't be set on fields of type %s",
			v, k, field.Type().Name(), val.Type().Name(),
		)
	}
	field.Set(val)
	return nil
}
