package config

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"os"
	"time"

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
	Prober    string        `yaml:"prober,omitempty"`
	Timeout   time.Duration `yaml:"timeout,omitempty"`
	TLSConfig TLSConfig     `yaml:"tls_config,omitempty"`
	HTTPS     HTTPSProbe    `yaml:"https,omitempty"`
	TCP       TCPProbe      `yaml:"tcp,omitempty"`
}

// TLSConfig configures the options for TLS connections.
type TLSConfig struct {
	CAFile             string     `yaml:"ca_file,omitempty"`
	CertFile           string     `yaml:"cert_file,omitempty"`
	KeyFile            string     `yaml:"key_file,omitempty"`
	ServerName         string     `yaml:"server_name,omitempty"`
	InsecureSkipVerify bool       `yaml:"insecure_skip_verify"`
	DANE               DANEConfig `yaml:"dane,omitempty"`
}

// DANEConfig configures DANE verification
type DANEConfig struct {
	Verify bool `yaml:"verify,omitempty"`
}

// NewTLSConfig creates a new tls.Config from the given TLSConfig
func NewTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	return config.NewTLSConfig(&config.TLSConfig{
		CAFile:             cfg.CAFile,
		CertFile:           cfg.CertFile,
		KeyFile:            cfg.KeyFile,
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})
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
