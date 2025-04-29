package util

import (
	"flag"
	"fmt"
	"os"
	"regexp"
)

type CLIArgs struct {
	RootIP string
}

func ParseArgs() (*CLIArgs, error) {
	help := flag.Bool("help", false, "Show help message")
	flag.Parse()

	if *help {
		printHelp()
		os.Exit(0)
	}

	// Get non-flag arguments
	args := flag.Args()
	if len(args) < 1 {
		return nil, fmt.Errorf("root IP address is required")
	}

	// Validate IP address format (basic validation)
	rootIP := args[0]
	if !isValidIP(rootIP) {
		return nil, fmt.Errorf("invalid IP address format: %s", rootIP)
	}

	return &CLIArgs{
		RootIP: args[0],
	}, nil
}

func printHelp() {
	fmt.Println("Network Topology Scanner")
	fmt.Println("Usage: saltopo [options] <root_ip>")
	fmt.Println("\nOptions:")
	fmt.Println("  -help\t\tShow this help message")
	fmt.Println("\nArguments:")
	fmt.Println("  root_ip\tIP address of the root device to start scanning from")
	fmt.Println("\nExample:")
	fmt.Println("  saltopo 192.168.1.1")
}

func isValidIP(ip string) bool {
	// regex to validate ip address
	ipRegex := `^(\d{1,3}\.){3}\d{1,3}$`
	matched, err := regexp.MatchString(ipRegex, ip)
	if err != nil || !matched {
		return false
	}

	return true
}
