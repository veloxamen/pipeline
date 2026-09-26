// Copyright 2026 CrabCanneryShip
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config loads configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strings"
)

// Config holds all runtime parameters for network-trigger.
type Config struct {
	// Port is the HTTP port the service listens on.
	Port string

	// GCPProject and Region locate the network-job Cloud Run Job.
	GCPProject     string
	Region         string
	NetworkJobName string

	// AllowedSrcBucket restricts processing to a specific bucket.
	AllowedSrcBucket string

	// SupportedLogTypes defines the set of parseable log types.
	SupportedLogTypes map[string]bool

	// PubSubAudience documents the expected OIDC audience.
	PubSubAudience string
}

// Load reads and validates configuration from environment variables.
func Load() (*Config, error) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	cfg := &Config{
		Port:              port,
		GCPProject:        os.Getenv("GOOGLE_CLOUD_PROJECT"),
		Region:            os.Getenv("GCP_REGION"),
		NetworkJobName:    os.Getenv("NETWORK_JOB_NAME"),
		AllowedSrcBucket:  os.Getenv("ALLOWED_SRC_BUCKET"),
		SupportedLogTypes: parseLogTypes(os.Getenv("SUPPORTED_LOG_TYPES")),
		PubSubAudience:    os.Getenv("PUBSUB_AUDIENCE"),
	}
	if cfg.NetworkJobName == "" {
		cfg.NetworkJobName = "network-job"
	}

	var missing []string
	for _, pair := range []struct{ name, val string }{
		{"GOOGLE_CLOUD_PROJECT", cfg.GCPProject},
		{"GCP_REGION", cfg.Region},
	} {
		if pair.val == "" {
			missing = append(missing, pair.name)
		}
	}
	if len(cfg.SupportedLogTypes) == 0 {
		missing = append(missing, "SUPPORTED_LOG_TYPES")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}

	return cfg, nil
}

func parseLogTypes(raw string) map[string]bool {
	set := make(map[string]bool)
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			set[t] = true
		}
	}
	return set
}
