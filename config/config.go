package config

import (
	"fmt"
	"net/url"
	"os"

	"github.com/prometheus/common/config"
	yaml "gopkg.in/yaml.v3"
)

var (
	DefaultConfig = &Config{
		map[string]Module{
			"tcp": Module{
				Prober: "tcp",
			},
			"http": Module{
				Prober: "https",
			},
			"https": Module{
				Prober: "https",
			},
		},
	}
)

func LoadConfig(confFile string) (*Config, error) {
	var c *Config

	yamlReader, err := os.Open(confFile)
	if err != nil {
		return c, fmt.Errorf("error reading config file: %s", err)
	}
	defer yamlReader.Close()
	decoder := yaml.NewDecoder(yamlReader)
	decoder.KnownFields(true)

	if err = decoder.Decode(&c); err != nil {
		return c, fmt.Errorf("error parsing config file: %s", err)
	}

	return c, nil

}

type Config struct {
	Modules map[string]Module `yaml:"modules"`
}

type Module struct {
	Prober    string           `yaml:"prober,omitempty"`
	TLSConfig config.TLSConfig `yaml:"tls_config,omitempty"`
	HTTPS     HTTPSProbe       `yaml:"https,omitempty"`
	TCP       TCPProbe         `yaml:"tcp,omitempty"`
}

type TCPProbe struct {
	StartTLS string `yaml:"starttls,omitempty"`
}

type HTTPSProbe struct {
	ProxyURL URL `yaml:"proxy_url,omitempty"`
}

// URL is a custom URL type that allows validation at configuration load time
type URL struct {
	*url.URL
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for URLs.
func (u *URL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	urlp, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.URL = urlp
	return nil
}
