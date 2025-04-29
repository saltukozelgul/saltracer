package topology

import (
	"Saltracer/config"
	"Saltracer/src/snmp"
	"Saltracer/src/types"
)

var currentTopology = types.Topology{
	Nodes:       make(map[int]*types.Node),
	Connections: make([]*types.Connection, 0),
}

func GetCurrentTopology() types.Topology {
	return currentTopology
}

// This function will start the discovery process from the root IP address
func DiscoverFromRoot(rootIP string) {
	// Create the root node and recursively discover the rest of the topology
	rootNode := types.Node{
		Index:      0,
		IPAddress:  rootIP,
		Type:       "router",
		Properties: map[string]interface{}{},
	}
	currentTopology.Nodes[rootNode.Index] = &rootNode

	// Discover the neighbors of the root node
	collector := snmp.SNMPCollector{
		Credentials: config.AppConfig.SnmpCredentials,
	}
	collector.FindNeighbors(&rootNode)

	// If code reaches here all the nodes have been discovered
	// now we can collect the data from the nodes
	for _, node := range currentTopology.Nodes {
		collector.Collect(node)
	}
}
