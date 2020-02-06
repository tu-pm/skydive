package snmp

// ChassisIDSubtypeMapping reference: https://github.com/google/gopacket/blob/master/layers/lldp.go#L45
var chassisIDSubtypeMapping = map[int]string{
	0: "Reserved",
	1: "Chassis Component",
	2: "Interface Alias",
	3: "Port Component",
	4: "MAC Address",
	5: "Network Address",
	6: "Interface Name",
	7: "Local",
}

// PortIDSubtypeMapping reference: https://github.com/google/gopacket/blob/master/layers/lldp.go#L79
var portIDSubtypeMapping = map[int]string{
	0: "Reserved",
	1: "Interface Alias",
	2: "Port Component",
	3: "MAC Address",
	4: "Network Address",
	5: "Interface Name",
	6: "Agent Circuit ID",
	7: "Local",
}

var stateMapping = map[int]string{
	1: "UP",
	2: "DOWN",
	3: "TESTING",
	4: "UNKNOWN",
	5: "DORMANT",
	6: "NOTPRESENT",
	7: "LOWERLAYERDOWN",
}

var mappings = map[string]map[int]string{
	"ChassisIDType": chassisIDSubtypeMapping,
	"PortIDType":    portIDSubtypeMapping,
	"State":         stateMapping,
}

// LLDP-MIB OIDs
var LldpLocalChassisOIDs = map[string]string{
	"Description":   ".1.0.8802.1.1.2.1.3.4.0",
	"ChassisID":     ".1.0.8802.1.1.2.1.3.2.0",
	"ChassisIDType": ".1.0.8802.1.1.2.1.3.1.0",
	"SysName":       ".1.0.8802.1.1.2.1.3.3.0",
}

var LldpRemotePortOIDs = map[string]string{
	"Description":            ".1.0.8802.1.1.2.1.4.1.1.8",
	"PVID":                   ".1.0.8802.1.1.2.1.5.32962.1.2.1.1.1",
	"VIDUsageDigest":         ".1.3.111.2.802.1.1.13.1.5.32962.1.3.5.1.1",
	"ManagementVID":          ".1.3.111.2.802.1.1.13.1.5.32962.1.3.6.1.1",
	"PortID":                 ".1.0.8802.1.1.2.1.4.1.1.7",
	"PortIDType":             ".1.0.8802.1.1.2.1.4.1.1.6",
	"LinkAggregation-Status": ".1.0.8802.1.1.2.1.5.4623.1.3.3.1.1",
	"LinkAggregation-PortID": ".1.0.8802.1.1.2.1.5.4623.1.3.3.1.2",
	"VLANNames-ID":           ".1.0.8802.1.1.2.1.5.32962.1.3.1.1.1",
	"VLANNames-Name":         ".1.0.8802.1.1.2.1.5.32962.1.3.3.1.2",
	"PPVIDs-Enabled":         ".1.0.8802.1.1.2.1.5.32962.1.3.2.1.3",
	"PPVIDs-ID":              ".1.0.8802.1.1.2.1.5.32962.1.3.2.1.1",
	"PPVIDs-Supported":       ".1.0.8802.1.1.2.1.5.32962.1.3.2.1.2",
	"MTU":                    ".1.0.8802.1.1.2.1.5.4623.1.3.4.1.1",
}

var LldpRemotePortIdOID = ".1.0.8802.1.1.2.1.4.1.1.7"

var LldpLocalPortOIDsMinimum = map[string]string{
	"Description": ".1.0.8802.1.1.2.1.3.7.1.4",
	"PortID":      ".1.0.8802.1.1.2.1.3.7.1.3",
	"PortIDType":  ".1.0.8802.1.1.2.1.3.7.1.2",
}

var LldpRemoteChassisMgmtAddressOID = ".1.0.8802.1.1.2.1.4.2.1.4"

// IF-MIB OIDs

var IfNameOID = "1.3.6.1.2.1.31.1.1.1.1"

var IfMetricOIDs = map[string]string{
	"IfInOctets":         ".1.3.6.1.2.1.2.2.1.10",
	"IfInUcastPkts":      ".1.3.6.1.2.1.2.2.1.11",
	"IfInMulticastPkts":  ".1.3.6.1.2.1.31.1.1.1.2",
	"IfInBroadcastPkts":  ".1.3.6.1.2.1.31.1.1.1.3",
	"IfInDiscards":       ".1.3.6.1.2.1.2.2.1.13",
	"IfInErrors":         ".1.3.6.1.2.1.2.2.1.14",
	"IfInUnknownProtos":  ".1.3.6.1.2.1.2.2.1.15",
	"IfOutOctets":        ".1.3.6.1.2.1.2.2.1.16",
	"IfOutUcastPkts":     ".1.3.6.1.2.1.2.2.1.17",
	"IfOutMulticastPkts": ".1.3.6.1.2.1.31.1.1.1.4",
	"IfOutBroadcastPkts": ".1.3.6.1.2.1.31.1.1.1.5",
	"IfOutDiscards":      ".1.3.6.1.2.1.2.2.1.19",
	"IfOutErrors":        ".1.3.6.1.2.1.2.2.1.20",
}

var IfConfigOIDs = map[string]string{
	"PhysicalAddress": ".1.3.6.1.2.1.2.2.1.6",
	"State":           ".1.3.6.1.2.1.2.2.1.8",
	"MTU":             ".1.3.6.1.2.1.2.2.1.4",
	"Speed":           ".1.3.6.1.2.1.2.2.1.5",
}
