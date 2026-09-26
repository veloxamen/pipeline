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

// Package config loads job configuration from environment variables.
package config

import (
	"fmt"
	"os"
)

// Config holds all runtime parameters for network-job.
type Config struct {
	// SrcBucket is the GCS bucket containing the raw log object.
	SrcBucket string
	// SrcObject is the single object to download and parse.
	SrcObject string
	// LogType selects the parser to use.
	LogType string

	// GCPProject, BQDataset, and BQTable locate the destination table.
	GCPProject string
	BQDataset  string
	BQTable    string

	// MappingConfigObject is the GCS object (within SrcBucket) holding
	// this log type's field-mapping config, used only when LogType is
	// not one of the built-in parsers (see internal/parser.Lookup).
	// Defaults to "config/<LOG_TYPE>.json", matching a bucket laid out
	// as [PROJECT]-nw/config/<name>.json alongside [PROJECT]-nw/log/<name>/.
	// Override via MAPPING_CONFIG_OBJECT if a different layout is used.
	MappingConfigObject string
}

// Load reads configuration from environment variables and validates that
// all required fields are present.
func Load() (*Config, error) {
	cfg := &Config{
		SrcBucket:           os.Getenv("SRC_BUCKET"),
		SrcObject:           os.Getenv("SRC_OBJECT"),
		LogType:             os.Getenv("LOG_TYPE"),
		GCPProject:          os.Getenv("GOOGLE_CLOUD_PROJECT"),
		BQDataset:           os.Getenv("BQ_DATASET"),
		BQTable:             os.Getenv("BQ_TABLE"),
		MappingConfigObject: os.Getenv("MAPPING_CONFIG_OBJECT"),
	}
	if cfg.BQTable == "" {
		cfg.BQTable = "network_events"
	}
	if cfg.MappingConfigObject == "" && cfg.LogType != "" {
		cfg.MappingConfigObject = "config/" + cfg.LogType + ".json"
	}

	var missing []string
	for _, pair := range []struct{ name, val string }{
		{"SRC_BUCKET", cfg.SrcBucket},
		{"SRC_OBJECT", cfg.SrcObject},
		{"LOG_TYPE", cfg.LogType},
		{"GOOGLE_CLOUD_PROJECT", cfg.GCPProject},
		{"BQ_DATASET", cfg.BQDataset},
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
