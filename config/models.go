package config

type Config struct {
	AppInfo         AppInfo           `yaml:"app_info"`
	SnmpCredentials []SnmpCredentials `yaml:"snmp_credentials"`
	RootIP          string            `yaml:"root_ip"`
}

type AppInfo struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Author      string `yaml:"author"`
	Description string `yaml:"description"`
}

type SnmpCredentials struct {
	Version      string `yaml:"version,omitempty"`
	Username     string `yaml:"username,omitempty"`
	Community    string `yaml:"community,omitempty"`
	PrivProtocol string `yaml:"priv_protocol,omitempty"`
	PrivKey      string `yaml:"priv_key,omitempty"`
	AuthProtocol string `yaml:"auth_protocol,omitempty"`
	AuthKey      string `yaml:"auth_key,omitempty"`
	Timeout      int    `yaml:"timeout,omitempty"`
	Retries      int    `yaml:"retries,omitempty"`
}
