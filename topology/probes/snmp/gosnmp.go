package snmp

import (
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/soniah/gosnmp"
)

// Client implements a wrapper around gosnmp.GoSNMP struct
// to provide additional functionalities for specific use cases
// in this package
type Client struct {
	gosnmp *gosnmp.GoSNMP
}

// NewSnmpClient create a new SNMP client
func NewSnmpClient(target, community string) *Client {
	return &Client{
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
func (c *Client) Connect() error {
	err := c.gosnmp.Connect()
	if err != nil {
		return errors.Wrapf(err, "Failed to connect to snmp agent at address %s", c.gosnmp.Target)
	}
	return nil
}

// Close closes current active connection
func (c *Client) Close() {
	c.gosnmp.Conn.Close()
}

// Walk is similar to gosnmp.GoSNMP.Walk
func (c *Client) Walk(rootOid string, walkFn gosnmp.WalkFunc) error {
	err := c.gosnmp.Walk(rootOid, walkFn)
	if err != nil {
		return errors.Wrapf(err, "SnmpWalk on root OID %s at address %s error", rootOid, c.gosnmp.Target)
	}
	return nil
}

// Get takes an OID and return snmpget result
func (c *Client) Get(oid string) (result interface{}, err error) {
	pkt, err := c.gosnmp.Get([]string{oid})
	if err != nil {
		err = errors.Wrapf(err, "SnmpGet on OID %s at address %s error", oid, c.gosnmp.Target)
		return
	}
	values, err := c.getPDUValues(pkt.Variables)
	if err != nil {
		err = errors.Wrapf(err, "SnmpGet unpack pdu values error")
		return
	}
	result = values[0]
	return
}

// GetMany takes a map of oids and return the result of snmpget command in a map
func (c *Client) GetMany(oids map[string]string, result Metadata) (err error) {
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
		if err = result.Set(label, values[i]); err != nil {
			err = errors.Wrapf(err, "SnmpGet setting fields error")
			return
		}
	}
	return
}

// GetNext takes an OID and return snmpgetnext result
func (c *Client) GetNext(oid string) (nextOID string, result interface{}, err error) {
	pkt, err := c.gosnmp.GetNext([]string{oid})
	if err != nil {
		err = errors.Wrapf(err, "SnmpGetNext on OID %s at address %s error", oid, c.gosnmp.Target)
		return
	}

	values, err := c.getPDUValues(pkt.Variables)
	if err != nil {
		err = errors.Wrapf(err, "SnmpGetNext unpack pdu values error")
		return
	}
	nextOID = pkt.Variables[0].Name
	result = values[0]
	return
}

// GetNextMany takes a map of oids and return the result of snmpgetnext command in a map
func (c *Client) GetNextMany(oids map[string]string, result Metadata) (nextOIDs map[string]string, err error) {
	nextOIDs = make(map[string]string)
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
		if err = result.Set(label, values[i]); err != nil {
			err = errors.Wrapf(err, "SnmpGetNext setting fields error")
			return
		}
	}
	return
}

func (c *Client) getPDUValue(pdu gosnmp.SnmpPDU) (interface{}, error) {
	switch pdu.Type {
	case gosnmp.OctetString:
		return decodeMACTest(pdu.Name, pdu.Value.([]byte)), nil
	case gosnmp.NoSuchObject:
		return nil, errors.New(
			fmt.Sprintf("OID %s doesn't exist at target %s", pdu.Name, c.gosnmp.Target),
		)
	default:
		return toInt64(pdu.Value), nil
	}
}

// Sometimes MAC addresses are encoded differently, typically when working with the lldpd tool
// got: [XX XX XX XX XX XX]
// want: "XX:XX:XX:XX:XX:XX"
func decodeMACTest(name string, val []byte) string {
	if len(val) == 6 && (strings.Contains(name, ".1.0.8802.1.1.2.1.4.1.1.7") ||
		strings.Contains(name, ".1.3.6.1.2.1.2.2.1.6") ||
		strings.Contains(name, ".1.0.8802.1.1.2.1.3.2.0") ||
		strings.Contains(name, ".1.0.8802.1.1.2.1.3.7.1.3")) {
		var hex []string
		for _, v := range val {
			hex = append(hex, fmt.Sprintf("%02x", v))
		}
		return strings.Join(hex, ":")
	}
	return string(val)
}

func (c *Client) getPDUValues(pdus []gosnmp.SnmpPDU) ([]interface{}, error) {
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
