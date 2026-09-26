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

// Config holds all runtime parameters for the Plaso job.
type Config struct {
	// SrcBucket is the GCS bucket containing decrypt-job output.
	SrcBucket string
	// CaseID identifies the forensic case.
	CaseID string
	// SrcPrefix is an optional prefix under SrcBucket.
	SrcPrefix string

	// DstBucket is the GCS bucket to write the resulting JSONL timeline.
	DstBucket string
	// DstPrefix is an optional prefix under DstBucket.
	DstPrefix string

	// PstealBin is the path or name of the psteal executable.
	PstealBin string

	// WorkDir is the local scratch directory for staging files.
	WorkDir string
}

// Load reads configuration from environment variables and validates that
// all required fields are present.
func Load() (*Config, error) {
	cfg := &Config{
		SrcBucket: os.Getenv("SRC_BUCKET"),
		CaseID:    os.Getenv("CASE_ID"),
		SrcPrefix: os.Getenv("SRC_PREFIX"),
		DstBucket: os.Getenv("DST_BUCKET"),
		DstPrefix: os.Getenv("DST_PREFIX"),
		PstealBin: os.Getenv("PSTEAL_BIN"),
		WorkDir:   os.Getenv("WORK_DIR"),
	}

	if cfg.PstealBin == "" {
		cfg.PstealBin = "psteal.py"
	}
	if cfg.WorkDir == "" {
		cfg.WorkDir = "/tmp/plaso-job"
	}

	var missing []string
	for _, pair := range []struct{ name, val string }{
		{"SRC_BUCKET", cfg.SrcBucket},
		{"CASE_ID", cfg.CaseID},
		{"DST_BUCKET", cfg.DstBucket},
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
