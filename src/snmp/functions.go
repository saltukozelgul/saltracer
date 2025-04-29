package snmp

import (
	"Saltracer/config"
	"Saltracer/src/types"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// OID constants
const (
	ifNameOID             = ".1.3.6.1.2.1.31.1.1.1.1"
	cdpCacheTableOID      = ".1.3.6.1.4.1.9.9.23.1.2.1.1"
	cdpCacheAddressOID    = ".1.3.6.1.4.1.9.9.23.1.2.1.1.4"
	cdpCacheDeviceIdOID   = ".1.3.6.1.4.1.9.9.23.1.2.1.1.6"
	cdpCacheDevicePortOID = ".1.3.6.1.4.1.9.9.23.1.2.1.1.7"
	cdpCacheIfIndexOID    = ".1.3.6.1.4.1.9.9.23.1.2.1.1.1"

	lldpRemTableOID          = ".1.0.8802.1.1.2.1.4.1.1"
	lldpRemLocalPortNumOID   = ".1.0.8802.1.1.2.1.4.1.1.2"
	lldpRemChassisIdOID      = ".1.0.8802.1.1.2.1.4.1.1.5"
	lldpRemPortIdOID         = ".1.0.8802.1.1.2.1.4.1.1.7"
	lldpRemSysNameOID        = ".1.0.8802.1.1.2.1.4.1.1.9"
	lldpRemManAddrTableOID   = ".1.0.8802.1.1.2.1.4.2.1"
	lldpRemManAddrSubtypeOID = ".1.0.8802.1.1.2.1.4.2.1.1"
	lldpRemManAddrOID        = ".1.0.8802.1.1.2.1.4.2.1.2"
)

type SNMPCollector struct {
	Credentials []config.SnmpCredentials
}

// Get the snmp client for the given credentials
func (c *SNMPCollector) GetClient(target string, credential config.SnmpCredentials) *gosnmp.GoSNMP {
	client := &gosnmp.GoSNMP{
		Target:  target,
		Port:    161,
		Timeout: time.Duration(credential.Timeout) * time.Second,
		Retries: credential.Retries,
	}

	switch credential.Version {
	case "2c":
		client.Version = gosnmp.Version2c
		client.Community = credential.Community
	case "3":
		client.Version = gosnmp.Version3
		client.SecurityModel = gosnmp.UserSecurityModel
		usmParams := &gosnmp.UsmSecurityParameters{
			UserName: credential.Username,
		}

		// Set Authentication Protocol
		switch credential.AuthProtocol {
		case "MD5":
			usmParams.AuthenticationProtocol = gosnmp.MD5
		case "SHA":
			usmParams.AuthenticationProtocol = gosnmp.SHA
		default:
			// Handle unsupported or default case if necessary
			// For now, we assume valid input or let gosnmp handle defaults
		}
		usmParams.AuthenticationPassphrase = credential.AuthKey

		// Set Privacy Protocol if PrivKey is provided
		if credential.PrivKey != "" {
			client.MsgFlags = gosnmp.AuthPriv // Use AuthPriv if privacy is enabled
			usmParams.PrivacyPassphrase = credential.PrivKey
			switch credential.PrivProtocol {
			case "DES":
				usmParams.PrivacyProtocol = gosnmp.DES
			case "AES":
				usmParams.PrivacyProtocol = gosnmp.AES
			default:
				// Handle unsupported or default case
			}
		} else {
			client.MsgFlags = gosnmp.AuthNoPriv // Use AuthNoPriv if only authentication is used
		}
		client.SecurityParameters = usmParams

	default:
		// Handle unknown version or return an error/default client
		fmt.Printf("Unsupported SNMP version: %s\n", credential.Version)
		return nil // Or return a default configuration if appropriate
	}

	return client
}

// Helper function to parse PDU values into common types
func parsePDUValue(pdu gosnmp.SnmpPDU) interface{} {
	switch pdu.Type {
	case gosnmp.OctetString, gosnmp.BitString:
		return string(pdu.Value.([]byte))
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.Counter64, gosnmp.TimeTicks:
		return gosnmp.ToBigInt(pdu.Value).Int64()
	case gosnmp.IPAddress:
		// Sometimes IPAddress comes as string, sometimes as bytes
		if valStr, ok := pdu.Value.(string); ok {
			return valStr
		} else if valBytes, ok := pdu.Value.([]byte); ok && len(valBytes) == 4 {
			return net.IP(valBytes).String()
		}
		return fmt.Sprintf("Invalid IP: %v", pdu.Value)
	case gosnmp.ObjectIdentifier:
		return pdu.Value.(string)
	case gosnmp.Null, gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
		return nil
	default:
		return pdu.Value // Return raw for unknown types
	}
}

// Helper to parse IP address bytes, potentially handling hex strings too
func parseIPAddress(value interface{}) string {
	if bytes, ok := value.([]byte); ok {
		if len(bytes) == 4 {
			return net.IP(bytes).String()
		} else if len(bytes) > 0 {
			// Check if it's a hex string representation of IP (sometimes seen)
			hexStr := string(bytes)
			if len(hexStr) == 8 { // Potential hex IPv4
				b, err := hex.DecodeString(hexStr)
				if err == nil && len(b) == 4 {
					return net.IP(b).String()
				}
			}
			return fmt.Sprintf("Non-IPv4 bytes: %x", bytes)
		}
	}
	if str, ok := value.(string); ok {
		return str // Assume it's already a string IP
	}
	return ""
}

// Gets a map of interface index to interface name (ifName)
func getLocalInterfaces(client *gosnmp.GoSNMP) (map[int64]string, error) {
	ifaces := make(map[int64]string)
	err := client.Walk(ifNameOID, func(pdu gosnmp.SnmpPDU) error {
		name := parsePDUValue(pdu)
		if nameStr, ok := name.(string); ok {
			// Extract index from OID: .1.3.6.1.2.1.31.1.1.1.1.INDEX
			parts := strings.Split(pdu.Name, ".")
			if len(parts) > 0 {
				if index, err := strconv.ParseInt(parts[len(parts)-1], 10, 64); err == nil {
					ifaces[index] = nameStr
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk ifName: %w", err)
	}
	return ifaces, nil
}

// Represents combined information about a discovered neighbor before creating topology objects
type neighborRawInfo struct {
	LocalIfIndex       int64
	NeighborIP         string
	NeighborDeviceID   string
	NeighborPortID     string
	NeighborSysName    string
	ManagementIPSubnet string // Needed for LLDP index matching
}

// Finds neighbors using CDP
func findNeighborsCDP(client *gosnmp.GoSNMP, sourceNode *types.Node, topology *types.Topology, localInterfaces map[int64]string) error {
	results := make(map[string]*neighborRawInfo) // Key: combined index derived from OID

	// Walk the CDP cache table
	err := client.Walk(cdpCacheTableOID, func(pdu gosnmp.SnmpPDU) error {
		// Key structure: .BASE_OID.COLUMN.ifIndex.deviceIndex
		oidParts := strings.Split(strings.TrimPrefix(pdu.Name, cdpCacheTableOID+"."), ".")
		if len(oidParts) < 3 {
			return nil // Invalid OID structure
		}
		instanceKey := oidParts[1] + "." + oidParts[2]

		if _, ok := results[instanceKey]; !ok {
			ifIndex, err := strconv.ParseInt(oidParts[1], 10, 64)
			if err != nil {
				return nil // Skip if cannot parse ifIndex
			}
			results[instanceKey] = &neighborRawInfo{LocalIfIndex: ifIndex}
		}

		val := parsePDUValue(pdu)
		valBytes, _ := pdu.Value.([]byte) // Need raw bytes for IP sometimes

		switch pdu.Name {
		case cdpCacheAddressOID + "." + instanceKey:
			if ipStr := parseIPAddress(valBytes); ipStr != "" && ipStr != "0.0.0.0" {
				results[instanceKey].NeighborIP = ipStr
			}
		case cdpCacheDeviceIdOID + "." + instanceKey:
			if str, ok := val.(string); ok {
				results[instanceKey].NeighborDeviceID = str
			}
		case cdpCacheDevicePortOID + "." + instanceKey:
			if str, ok := val.(string); ok {
				results[instanceKey].NeighborPortID = str
			}
		}
		return nil
	})

	if err != nil && !strings.Contains(err.Error(), "NoSuchName") { // Ignore NoSuchName errors if table is empty
		return fmt.Errorf("failed to walk CDP table: %w", err)
	}

	// Process collected CDP neighbor info
	for _, info := range results {
		if info.NeighborIP == "" {
			continue // Skip neighbors without a valid IP
		}

		localIfName := localInterfaces[info.LocalIfIndex]
		if localIfName == "" {
			localIfName = fmt.Sprintf("ifIndex %d", info.LocalIfIndex) // Fallback
		}

		// Find or create the neighbor node
		neighborNode, exists := topology.Nodes[info.NeighborIP]
		if !exists {
			neighborNode = &types.Node{
				ID:          info.NeighborIP,
				IPAddress:   info.NeighborIP,
				Properties:  make(map[string]interface{}),
				Neighbors:   make([]*types.Node, 0),
				Connections: make([]*types.Connection, 0),
			}
			topology.Nodes[info.NeighborIP] = neighborNode
			fmt.Println("[+] ", neighborNode.IPAddress)
		}

		// Create the connection
		connection := &types.Connection{
			Source:      sourceNode,
			Destination: neighborNode,
			Type:        "CDP",
			Properties: map[string]interface{}{
				"local_interface":  localIfName,
				"remote_interface": info.NeighborPortID,
				"remote_device_id": info.NeighborDeviceID,
			},
		}

		// Add connection to topology and nodes (avoid duplicates)
		topology.Connections = append(topology.Connections, connection)
		foundConn := false
		for _, c := range sourceNode.Connections {
			if c.Destination.ID == neighborNode.ID && c.Type == "CDP" { // Simple check
				foundConn = true
				break
			}
		}
		if !foundConn {
			sourceNode.Connections = append(sourceNode.Connections, connection)
		}
		// neighborNode.Connections is implicitly handled by the topology-wide list

		// Add neighbor relationship (avoid duplicates)
		foundNeighbor := false
		for _, n := range sourceNode.Neighbors {
			if n.ID == neighborNode.ID {
				foundNeighbor = true
				break
			}
		}
		if !foundNeighbor {
			sourceNode.Neighbors = append(sourceNode.Neighbors, neighborNode)
		}

		// Add back-reference to neighbor (if it doesn't exist)
		foundBackNeighbor := false
		for _, n := range neighborNode.Neighbors {
			if n.ID == sourceNode.ID {
				foundBackNeighbor = true
				break
			}
		}
		if !foundBackNeighbor {
			neighborNode.Neighbors = append(neighborNode.Neighbors, sourceNode)
		}

	}
	return nil
}

// Finds neighbors using LLDP
func findNeighborsLLDP(client *gosnmp.GoSNMP, sourceNode *types.Node, topology *types.Topology, localInterfaces map[int64]string) error {
	// 1. Walk LLDP Remote Table
	remoteInfo := make(map[string]*neighborRawInfo) // Key: localPortNum.remIndex
	err := client.Walk(lldpRemTableOID, func(pdu gosnmp.SnmpPDU) error {
		// Key structure: .BASE_OID.COLUMN.timeMark.localPortNum.remIndex
		oidPrefix := lldpRemTableOID + "."
		if !strings.HasPrefix(pdu.Name, oidPrefix) {
			return nil
		}
		oidSuffix := strings.TrimPrefix(pdu.Name, oidPrefix)
		oidParts := strings.Split(oidSuffix, ".")
		if len(oidParts) < 4 {
			return nil // Need at least column, timeMark, localPortNum, remIndex
		}

		localPortNumStr := oidParts[2]
		remIndexStr := oidParts[3]
		instanceKey := localPortNumStr + "." + remIndexStr

		if _, ok := remoteInfo[instanceKey]; !ok {
			localPortNum, err := strconv.ParseInt(localPortNumStr, 10, 64)
			if err != nil {
				fmt.Printf("LLDP: Error parsing localPortNum %s: %v\n", localPortNumStr, err)
				return nil // Skip if cannot parse localPortNum
			}
			remoteInfo[instanceKey] = &neighborRawInfo{LocalIfIndex: localPortNum}
		}

		val := parsePDUValue(pdu)
		baseOIDWithColumn := oidPrefix + oidParts[0]

		switch baseOIDWithColumn {
		case lldpRemChassisIdOID:
			if str, ok := val.(string); ok {
				// Chassis ID might be MAC, try formatting
				if len(pdu.Value.([]byte)) == 6 {
					remoteInfo[instanceKey].NeighborDeviceID = net.HardwareAddr(pdu.Value.([]byte)).String()
				} else {
					remoteInfo[instanceKey].NeighborDeviceID = str
				}
			}
		case lldpRemPortIdOID:
			if str, ok := val.(string); ok {
				remoteInfo[instanceKey].NeighborPortID = str
			}
		case lldpRemSysNameOID:
			if str, ok := val.(string); ok {
				remoteInfo[instanceKey].NeighborSysName = str
			}
		}
		return nil
	})

	if err != nil && !strings.Contains(err.Error(), "NoSuchName") {
		fmt.Printf("LLDP: Failed to walk remote table for %s: %v\n", client.Target, err)
		// Continue to try processing management addresses if possible
	}

	// 2. Walk LLDP Management Address Table to find IPs
	mangagementIPs := make(map[string]string) // Key: timeMark.localPortNum.remIndex.manAddrSubtype.manAddr
	err = client.Walk(lldpRemManAddrTableOID, func(pdu gosnmp.SnmpPDU) error {
		// Key structure: .BASE_OID.COLUMN.timeMark.localPortNum.remIndex.manAddrSubtype.manAddr
		oidPrefix := lldpRemManAddrTableOID + "."
		if !strings.HasPrefix(pdu.Name, oidPrefix) {
			return nil
		}
		oidSuffix := strings.TrimPrefix(pdu.Name, oidPrefix)
		oidParts := strings.Split(oidSuffix, ".")
		if len(oidParts) < 6 {
			return nil // Need column, timeMark, localPortNum, remIndex, manAddrSubtype, manAddr
		}

		// manAddrSubtypeStr := oidParts[4]
		// manAddrParts := oidParts[5:] // The actual address can have multiple parts for IPv6

		instanceKey := strings.Join(oidParts[1:], ".") // timeMark.localPortNum...manAddr
		baseOIDWithColumn := oidPrefix + oidParts[0]

		switch baseOIDWithColumn {
		case lldpRemManAddrSubtypeOID:
			// Check if it's IPv4 (subtype 1)
			if manAddrSubtype, ok := parsePDUValue(pdu).(int64); ok && manAddrSubtype == 1 {
				mangagementIPs[instanceKey] = "" // Mark as potential IPv4, IP will be set below
			}
		case lldpRemManAddrOID:
			if _, isIPv4 := mangagementIPs[instanceKey]; isIPv4 {
				valBytes, _ := pdu.Value.([]byte)
				if ipStr := parseIPAddress(valBytes); ipStr != "" {
					mangagementIPs[instanceKey] = ipStr
				}
			}
		}
		return nil
	})

	if err != nil && !strings.Contains(err.Error(), "NoSuchName") {
		return fmt.Errorf("failed to walk LLDP management address table: %w", err)
	}

	// 3. Correlate remote info with management IPs
	for remoteKey, info := range remoteInfo {
		foundIP := ""
		// remoteKey = localPortNum.remIndex
		// mgmtKey = timeMark.localPortNum.remIndex.manAddrSubtype.manAddr
		for mgmtKey, ip := range mangagementIPs {
			mgmtKeyParts := strings.Split(mgmtKey, ".")
			if len(mgmtKeyParts) > 3 {
				// Check if localPortNum and remIndex match
				mgmtRemoteKey := mgmtKeyParts[1] + "." + mgmtKeyParts[2] // localPortNum.remIndex
				if mgmtRemoteKey == remoteKey && ip != "" && ip != "0.0.0.0" {
					foundIP = ip
					break // Found first valid IPv4 management address for this neighbor
				}
			}
		}

		if foundIP == "" {
			// fmt.Printf("LLDP: No management IP found for neighbor on local ifIndex %d\n", info.LocalIfIndex)
			continue // Skip neighbors without a usable management IP
		}
		info.NeighborIP = foundIP

		localIfName := localInterfaces[info.LocalIfIndex]
		if localIfName == "" {
			localIfName = fmt.Sprintf("ifIndex %d", info.LocalIfIndex) // Fallback
		}

		// Find or create the neighbor node
		neighborNode, exists := topology.Nodes[info.NeighborIP]
		if !exists {
			neighborNode = &types.Node{
				ID:          info.NeighborIP,
				IPAddress:   info.NeighborIP,
				Properties:  make(map[string]interface{}),
				Neighbors:   make([]*types.Node, 0),
				Connections: make([]*types.Connection, 0),
			}
			topology.Nodes[info.NeighborIP] = neighborNode
		}

		// Create the connection
		connection := &types.Connection{
			Source:      sourceNode,
			Destination: neighborNode,
			Type:        "LLDP",
			Properties: map[string]interface{}{
				"local_interface":    localIfName,
				"remote_interface":   info.NeighborPortID,
				"remote_chassis_id":  info.NeighborDeviceID, // Stored ChassisID here
				"remote_system_name": info.NeighborSysName,
			},
		}

		// Add connection to topology and nodes (avoid duplicates)
		topology.Connections = append(topology.Connections, connection)
		foundConn := false
		for _, c := range sourceNode.Connections {
			if c.Destination.ID == neighborNode.ID && c.Type == "LLDP" { // Simple check
				foundConn = true
				break
			}
		}
		if !foundConn {
			sourceNode.Connections = append(sourceNode.Connections, connection)
		}
		// neighborNode.Connections is implicitly handled by the topology-wide list

		// Add neighbor relationship (avoid duplicates)
		foundNeighbor := false
		for _, n := range sourceNode.Neighbors {
			if n.ID == neighborNode.ID {
				foundNeighbor = true
				break
			}
		}
		if !foundNeighbor {
			sourceNode.Neighbors = append(sourceNode.Neighbors, neighborNode)
		}

		// Add back-reference to neighbor (if it doesn't exist)
		foundBackNeighbor := false
		for _, n := range neighborNode.Neighbors {
			if n.ID == sourceNode.ID {
				foundBackNeighbor = true
				break
			}
		}
		if !foundBackNeighbor {
			neighborNode.Neighbors = append(neighborNode.Neighbors, sourceNode)
		}
	}

	return nil
}

// This function will find the neighbors of the node via CDP/LLDP and update the topology
func (c *SNMPCollector) FindNeighbors(node *types.Node, topology *types.Topology, depth int) {
	fmt.Println("[+] ", node.IPAddress)
	found := false
	for _, credential := range c.Credentials {
		client := c.GetClient(node.IPAddress, credential)
		if client == nil {
			fmt.Printf("Skipping credential for %s due to unsupported config\n", node.IPAddress)
			continue
		}

		err := client.Connect()
		if err != nil {
			continue // Next cred
		}
		defer client.Conn.Close()

		// Get Local Interfaces
		localInterfaces, err := getLocalInterfaces(client)
		if err != nil {
			fmt.Printf("Could not get local interfaces for %s: %v\n", node.IPAddress, err)
			continue // Next cred
		}

		// Try CDP
		errCDP := findNeighborsCDP(client, node, topology, localInterfaces)
		if errCDP == nil {
			found = true
		}

		// Try LLDP
		errLLDP := findNeighborsLLDP(client, node, topology, localInterfaces)
		if errLLDP == nil {
			found = true
		}

		if found {
			break
		}
	}
	if !found {
		fmt.Printf("Failed to connect and perform neighbor discovery on %s with any credential.\n", node.IPAddress)
	}
}

// This function will collect the data from the node using SNMP like sysDescr, sysName etc.
func (c *SNMPCollector) Collect(node *types.Node) {
	for _, credential := range c.Credentials {
		client := c.GetClient(node.IPAddress, credential)
		if client == nil {
			continue
		}

		err := client.Connect()
		if err != nil {
			continue
		}

		defer client.Conn.Close()

		oids := []string{
			".1.3.6.1.2.1.1.1.0", // sysDescr
			".1.3.6.1.2.1.1.5.0", // sysName
		}
		result, err := client.Get(oids)
		if err != nil {
			continue
		}

		for _, variable := range result.Variables {
			if variable.Type == gosnmp.OctetString {
				switch variable.Name {
				case ".1.3.6.1.2.1.1.1.0":
					node.Properties["sysDescr"] = parsePDUValue(variable)
				case ".1.3.6.1.2.1.1.5.0":
					node.Properties["sysName"] = parsePDUValue(variable)
				}
			}
		}
		break
	}
}
