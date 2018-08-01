// Package config is concerned with acquiring the
// configuration for the program.
package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jjeffery/hclconfig"
)

// Config represents the structure of the configuration file.
type Config struct {
	SiteURL      string
	StaticAssets StaticConfig
	Session      SessionConfig
	OAuth2       OAuth2Config
	Environment  Environment
}

// StaticConfig contains the configuration for the static assets.
type StaticConfig struct {
	URL   string
	Allow []string // list of paths that do not require authentication

	// Deprecated: use URL instead. If URL is not supplied and
	// Bucket is supplied, then URL is constructed from Bucket and Prefix.
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
	LandingURL   string
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
	log.Println("loaded config:", configLocation)

	var configFile Config

	if err := file.Decode(&configFile); err != nil {
		return err
	}
	configFile.Environment = normalize(configFile.Environment)

	// For backwards compatibility, build an S3 URL if only Bucket and Prefix are provided.
	if configFile.StaticAssets.URL == "" && configFile.StaticAssets.Bucket != "" {
		configFile.StaticAssets.URL = fmt.Sprintf("s3://%s/%s",
			configFile.StaticAssets.Bucket,
			strings.TrimPrefix(configFile.StaticAssets.Prefix, "/"))
	}
	configFile.StaticAssets.Bucket = "" // deprecated
	configFile.StaticAssets.Prefix = "" // deprecated

	File = configFile

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
