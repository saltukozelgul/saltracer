package topology

import (
	"Saltracer/config"
	"Saltracer/src/snmp"
	"Saltracer/src/types"
)

var currentTopology = types.Topology{
	Nodes:       make(map[string]*types.Node),
	Connections: make([]*types.Connection, 0),
}

// This function will start the discovery process from the root IP address
func DiscoverFromRoot(rootIP string) {
	// Create the root node and recursively discover the rest of the topology
	rootNode := types.Node{
		ID:         rootIP,
		IPAddress:  rootIP,
		Type:       "router",
		Properties: map[string]interface{}{},
	}
	currentTopology.Nodes[rootNode.ID] = &rootNode

	// Discover the neighbors of the root node
	collector := snmp.SNMPCollector{
		Credentials: config.AppConfig.SnmpCredentials,
	}
	collector.FindNeighbors(&rootNode, &currentTopology, 0)

	// If code reaches here all the nodes have been discovered
	// now we can collect the data from the nodes
	// for _, node := range currentTopology.Nodes {
	// 	collector.Collect(node)
	// }
}
