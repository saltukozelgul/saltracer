package types

type Node struct {
	ID          string
	IPAddress   string
	Type        string
	Properties  map[string]interface{}
	Neighbors   []*Node
	Connections []*Connection
}

type Connection struct {
	Source      *Node
	Destination *Node
	Type        string
	Properties  map[string]interface{}
}

type Topology struct {
	Nodes       map[string]*Node
	Connections []*Connection
}
