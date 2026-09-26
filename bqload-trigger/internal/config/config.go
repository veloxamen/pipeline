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
)

// Config holds all runtime parameters for the BigQuery load trigger.
type Config struct {
	Port             string
	GCPProject       string
	BQDataset        string
	BQTable          string
	AllowedSrcBucket string
	PubSubAudience   string
}

// Load reads and validates configuration from environment variables.
func Load() (*Config, error) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	cfg := &Config{
		Port:             port,
		GCPProject:       os.Getenv("GOOGLE_CLOUD_PROJECT"),
		BQDataset:        os.Getenv("BQ_DATASET"),
		BQTable:          os.Getenv("BQ_TABLE"),
		AllowedSrcBucket: os.Getenv("ALLOWED_SRC_BUCKET"),
		PubSubAudience:   os.Getenv("PUBSUB_AUDIENCE"),
	}

	var missing []string
	for _, pair := range []struct{ name, val string }{
		{"GOOGLE_CLOUD_PROJECT", cfg.GCPProject},
		{"BQ_DATASET", cfg.BQDataset},
		{"BQ_TABLE", cfg.BQTable},
	} {
		if pair.val == "" {
			missing = append(missing, pair.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}

	return cfg, nil
}
