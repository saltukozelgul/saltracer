package util

import (
	"Saltracer/config"
	"fmt"
)

func Initialize() error {
	args, err := ParseArgs()
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}

	_, err = config.LoadConfig("assets/config.yaml")
	if err != nil {
		fmt.Println("Error loading config:", err)
		return err
	}

	// Store the root IP in the config
	config.AppConfig.RootIP = args.RootIP

	PrintMOTD()
	return nil
}

func PrintMOTD() {
	ASCII_ART := `
	███████╗ █████╗ ██╗     ████████╗██████╗  █████╗  ██████╗███████╗██████╗ 
	██╔════╝██╔══██╗██║     ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗
	███████╗███████║██║        ██║   ██████╔╝███████║██║     █████╗  ██████╔╝
	╚════██║██╔══██║██║        ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══██╗
	███████║██║  ██║███████╗   ██║   ██║  ██║██║  ██║╚██████╗███████╗██║  ██║
	╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝
	`
	fmt.Println(ASCII_ART)
	fmt.Println("Welcome to the", config.AppConfig.AppInfo.Name)
	fmt.Println("Version:", config.AppConfig.AppInfo.Version)
	fmt.Println("Author:", config.AppConfig.AppInfo.Author)
}
