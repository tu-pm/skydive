package snmp

import (
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/soniah/gosnmp"
)

// SnmpClient implements a wrapper around gosnmp.GoSNMP struct
// to provide additional functionalities for specific use cases
// in this package
type SnmpClient struct {
	gosnmp *gosnmp.GoSNMP
}

func NewSnmpClient(target, community string) *SnmpClient {
	return &SnmpClient{
		gosnmp: &gosnmp.GoSNMP{
			Port:               161,
			Transport:          "udp",
			Community:          community,
			Version:            gosnmp.Version2c,
			Timeout:            time.Duration(2) * time.Second,
			Retries:            3,
			ExponentialTimeout: true,
			MaxOids:            gosnmp.MaxOids,
			Target:             target,
		},
	}
}

// Connect is similar to gosnmp.GoSNMP.Connect
func (c *SnmpClient) Connect() error {
	err := c.gosnmp.Connect()
	if err != nil {
		return errors.Wrapf(err, "Failed to connect to snmp agent at address %s", c.gosnmp.Target)
	}
	return nil
}

// Close closes current active connection
func (c *SnmpClient) Close() {
	c.gosnmp.Conn.Close()
}

// Walk is similar to gosnmp.GoSNMP.Walk
func (c *SnmpClient) Walk(rootOid string, walkFn gosnmp.WalkFunc) error {
	err := c.gosnmp.Walk(rootOid, walkFn)
	if err != nil {
		return errors.Wrapf(err, "SnmpWalk on root OID %s at address %s error", rootOid, c.gosnmp.Target)
	}
	return nil
}

// Get is similar to gosnmp.GoSNMP.Get, but the oids parameter is a
// map from oid label to oid string
func (c *SnmpClient) Get(oids map[string]string) (result *SnmpPayload, err error) {
	result = &SnmpPayload{}
	oidLabels, oidStrings := []string{}, []string{}
	for label, oid := range oids {
		oidLabels = append(oidLabels, label)
		oidStrings = append(oidStrings, oid)
	}
	pkt, err := c.gosnmp.Get(oidStrings)
	if err != nil {
		err = errors.Wrapf(err, "SnmpGet on OIDs %v at address %s error", oidStrings, c.gosnmp.Target)
		return
	}
	values, err := c.getPDUValues(pkt.Variables)
	if err != nil {
		err = errors.Wrapf(err, "SnmpGet unpack pdu values error")
		return
	}
	for i, label := range oidLabels {
		result.SetValue(label, values[i])
	}
	return
}

// GetNext is similar to gosnmp.GoSNMP.GetNext, but instead of a slice
// of oid string, it receives a map from oid label to oid string
func (c *SnmpClient) GetNext(oids map[string]string) (nextOIDs map[string]string, result *SnmpPayload, err error) {
	nextOIDs = make(map[string]string)
	result = &SnmpPayload{}
	oidStrings := []string{}
	oidLabels, oidStrings := []string{}, []string{}
	for label, oid := range oids {
		oidLabels = append(oidLabels, label)
		oidStrings = append(oidStrings, oid)
	}
	pkt, err := c.gosnmp.GetNext(oidStrings)
	if err != nil {
		err = errors.Wrapf(err, "SnmpGetNext on OIDs %v at address %s error", oidStrings, c.gosnmp.Target)
		return
	}
	values, err := c.getPDUValues(pkt.Variables)
	if err != nil {
		err = errors.Wrapf(err, "SnmpGetNext unpack pdu values error")
		return
	}
	for i, label := range oidLabels {
		nextOIDs[label] = pkt.Variables[i].Name
		result.SetValue(label, values[i])
	}
	return
}

func (c *SnmpClient) getPDUValue(pdu gosnmp.SnmpPDU) (interface{}, error) {
	switch pdu.Type {
	case gosnmp.OctetString:
		// NOTE: Hard code here to work with lldpd emulation tool.
		pVal := pdu.Value.([]byte)
		if (strings.Contains(pdu.Name, ".1.0.8802.1.1.2.1.4.1.1.7") ||
			strings.Contains(pdu.Name, "1.3.6.1.2.1.2.2.1.6") ||
			strings.Contains(pdu.Name, ".1.0.8802.1.1.2.1.3.2.0")) &&
			len(pVal) == 6 {
			hex_ := [6]string{}
			hex := hex_[:]
			for i, v := range pVal {
				hex[i] = fmt.Sprintf("%02x", v)
			}
			return strings.Join(hex, ":"), nil
		} else {
			return string(pVal), nil
		}
	case gosnmp.NoSuchObject:
		return nil, errors.New(
			fmt.Sprintf("OID %s doesn't exist at target %s", pdu.Name, c.gosnmp.Target),
		)
	default:
		return toInt64(pdu.Value), nil
	}
}

func (c *SnmpClient) getPDUValues(pdus []gosnmp.SnmpPDU) ([]interface{}, error) {
	var res []interface{}
	for _, pdu := range pdus {
		val, err := c.getPDUValue(pdu)
		if err != nil {
			return nil, err
		}
		res = append(res, val)
	}
	return res, nil
}

func toInt64(value interface{}) int64 {
	var val int64
	switch value := value.(type) { // shadow
	case int:
		val = int64(value)
	case int8:
		val = int64(value)
	case int16:
		val = int64(value)
	case int32:
		val = int64(value)
	case int64:
		val = int64(value)
	case uint:
		val = int64(value)
	case uint8:
		val = int64(value)
	case uint16:
		val = int64(value)
	case uint32:
		val = int64(value)
	default:
		val = int64(0)
	}
	return val
}
