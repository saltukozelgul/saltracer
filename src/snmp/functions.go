package snmp

import (
	"Saltracer/config"
	"Saltracer/src/types"
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
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

// This function will find the neighbors of the node via CDP/LLDP
func (c *SNMPCollector) FindNeighbors(node *types.Node) {

}

// This function will collect the data from the node using SNMP like sysDescr, sysName etc.
func (c *SNMPCollector) Collect(node *types.Node) {
	fmt.Println("Collecting data from node:", node.IPAddress)
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
					node.Properties["sysDescr"] = string(variable.Value.([]byte))
				case ".1.3.6.1.2.1.1.5.0":
					node.Properties["sysName"] = string(variable.Value.([]byte))
				}
			}
		}
		fmt.Println(node.Properties)
		break
	}
}
