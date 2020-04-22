package snmp

// 1. LLDP-MIB OIDs

// LldpLocalChassisOIDs store local system information
var LldpLocalChassisOIDs = map[string]string{
	"Description":   ".1.0.8802.1.1.2.1.3.4.0",
	"ChassisID":     ".1.0.8802.1.1.2.1.3.2.0",
	"ChassisIDType": ".1.0.8802.1.1.2.1.3.1.0",
	"SysName":       ".1.0.8802.1.1.2.1.3.3.0",
}

// LldpRemotePortIDOID store remote system's port ids
var LldpRemotePortIDOID = ".1.0.8802.1.1.2.1.4.1.1.7"

// LldpLocalPortOIDs store local port information
var LldpLocalPortOIDs = map[string]string{
	"Description": ".1.0.8802.1.1.2.1.3.7.1.4",
	"PortID":      ".1.0.8802.1.1.2.1.3.7.1.3",
	"PortIDType":  ".1.0.8802.1.1.2.1.3.7.1.2",
}

// LldpRemoteChassisMgmtAddressOID store remote management addresses
var LldpRemoteChassisMgmtAddressOID = ".1.0.8802.1.1.2.1.4.2.1.4"

// 2. IF-MIB OIDs

// IfNameOID store system's port names
var IfNameOID = "1.3.6.1.2.1.31.1.1.1.1"

// IfDescrOID store system's port descriptions
var IfDescrOID = "1.3.6.1.2.1.2.2.1.2"

// IfMetricOIDs store system's port metrics
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

// IfConfigOIDs store system's port configs
var IfConfigOIDs = map[string]string{
	"PhysicalAddress": ".1.3.6.1.2.1.2.2.1.6",
	"State":           ".1.3.6.1.2.1.2.2.1.8",
	"MTU":             ".1.3.6.1.2.1.2.2.1.4",
	"Speed":           ".1.3.6.1.2.1.2.2.1.5",
}
