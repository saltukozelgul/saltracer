package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Static config instance that can be accessed from anywhere
var AppConfig *Config

func LoadConfig(path string) (*Config, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(yamlFile, &AppConfig)
	if err != nil {
		return nil, err
	}

	snmpCredentials, err := GetSnmpCredentials()
	if err != nil {
		return nil, err
	}

	AppConfig.SnmpCredentials = snmpCredentials

	return AppConfig, nil
}

func GetSnmpCredentials() ([]SnmpCredentials, error) {
	yamlFile, err := os.ReadFile("assets/credentials.yaml")
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(yamlFile, &AppConfig)
	if err != nil {
		return nil, err
	}

	return AppConfig.SnmpCredentials, nil
}
