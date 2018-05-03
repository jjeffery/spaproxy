// Package config is concerned with acquiring the
// configuration for the program.
package config

import (
	"os"

	"github.com/jjeffery/hclconfig"
)

// Config represents the structure of the configuration file.
type Config struct {
	SiteURL      string
	StaticAssets S3Config
	Session      SessionConfig
	OAuth2       OAuth2Config
	Environment  Environment
}

// S3Config contains the configuration for the S3 static assets.
type S3Config struct {
	Bucket string
	Prefix string
}

// SessionConfig contains the configuration for sessions and session cookies.
type SessionConfig struct {
	Table          string
	Secret         string
	PreviousSecret string
	MaxAge         int
}

// OAuth2Config contains the configuration for the OAuth server.
type OAuth2Config struct {
	AuthURL      string
	TokenURL     string
	LogoutURL    string
	ClientID     string
	ClientSecret string
}

// Environment contains arbitrary environment-specific information.
type Environment map[string]interface{}

var (
	// File is the variable where the configuration is loaded.
	File Config
)

// Load the config from the config file. The config file or URL
// is specified by the environment variable "CONFIG_FILE", or
// the default is "local.hcl".
func Load() error {
	configLocation := os.Getenv("CONFIG")
	if configLocation == "" {
		configLocation = "local.hcl"
	}
	file, err := hclconfig.Get(configLocation)
	if err != nil {
		return err
	}

	if err := file.Decode(&File); err != nil {
		return err
	}

	File.Environment = normalize(File.Environment)

	return nil
}

func normalize(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		m = make(map[string]interface{})
	}
	for k, v := range m {
		if arr, ok := v.([]map[string]interface{}); ok {
			if len(arr) == 1 {
				m[k] = normalize(arr[0])
			} else {
				for i := range arr {
					arr[i] = normalize(arr[i])
				}
			}
		} else if mm, ok := v.(map[string]interface{}); ok {
			m[k] = normalize(mm)
		}
	}
	return m
}
