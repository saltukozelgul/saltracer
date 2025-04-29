package main

import (
	"Saltracer/config"
	"Saltracer/src/topology"
	"Saltracer/src/util"
)

func main() {
	err := util.Initialize()
	if err != nil {
		return
	}
	topology.DiscoverFromRoot(config.AppConfig.RootIP)
}
