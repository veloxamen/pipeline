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
	"strconv"
	"time"
)

// Config holds all runtime parameters for plaso-trigger.
type Config struct {
	// Port is the HTTP port the service listens on.
	Port string

	// GCPProject and Region locate where jobs are submitted.
	GCPProject string
	Region     string

	// AllowedSrcBucket restricts processing to a specific bucket.
	AllowedSrcBucket string

	// CaseID is this deployment's case identifier.
	CaseID string

	// PlasoJobImage is the full Artifact Registry image URI for plaso-job.
	PlasoJobImage string
	// PlasoJobSA is the service account plaso-job runs as.
	PlasoJobSA string
	// SrcBucket/DstBucket are plaso-job's bucket configuration parameters.
	SrcBucket string
	DstBucket string

	// MachineType is the Compute Engine machine type for the Batch VM.
	MachineType string
	// CPUMilli/MemoryMib are the per-task compute resource requests.
	CPUMilli  int64
	MemoryMib int64
	// ScratchDiskGB is the size of the Persistent Disk attached to the Batch VM.
	ScratchDiskGB int64
	// ProvisioningModel is either "STANDARD" or "SPOT".
	ProvisioningModel string
	// MaxRetryCount is the number of times Batch will retry the task on failure.
	MaxRetryCount int32
	// MaxRunDuration bounds a single task attempt.
	MaxRunDuration time.Duration

	// PubSubAudience documents the expected OIDC audience for the push subscription.
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
		AllowedSrcBucket:  os.Getenv("ALLOWED_SRC_BUCKET"),
		CaseID:            os.Getenv("CASE_ID"),
		PlasoJobImage:     os.Getenv("PLASO_JOB_IMAGE"),
		PlasoJobSA:        os.Getenv("PLASO_JOB_SA"),
		SrcBucket:         os.Getenv("SRC_BUCKET"),
		DstBucket:         os.Getenv("DST_BUCKET"),
		MachineType:       os.Getenv("PLASO_MACHINE_TYPE"),
		ProvisioningModel: os.Getenv("PLASO_PROVISIONING_MODEL"),
		PubSubAudience:    os.Getenv("PUBSUB_AUDIENCE"),
	}

	var err error
	if cfg.CPUMilli, err = parseInt64Env("PLASO_CPU_MILLI", 8000); err != nil {
		return nil, err
	}
	if cfg.MemoryMib, err = parseInt64Env("PLASO_MEMORY_MIB", 32768); err != nil {
		return nil, err
	}
	if cfg.ScratchDiskGB, err = parseInt64Env("PLASO_DISK_GB", 500); err != nil {
		return nil, err
	}
	maxRetry, err := parseInt64Env("PLASO_MAX_RETRY_COUNT", 2)
	if err != nil {
		return nil, err
	}
	cfg.MaxRetryCount = int32(maxRetry)

	maxRunDurationStr := os.Getenv("PLASO_MAX_RUN_DURATION")
	if maxRunDurationStr == "" {
		maxRunDurationStr = "12h"
	}
	cfg.MaxRunDuration, err = time.ParseDuration(maxRunDurationStr)
	if err != nil {
		return nil, fmt.Errorf("invalid PLASO_MAX_RUN_DURATION %q: %w", maxRunDurationStr, err)
	}

	if cfg.MachineType == "" {
		cfg.MachineType = "n2-highmem-16"
	}
	if cfg.ProvisioningModel == "" {
		cfg.ProvisioningModel = "STANDARD"
	}
	if cfg.ProvisioningModel != "SPOT" && cfg.ProvisioningModel != "STANDARD" {
		return nil, fmt.Errorf("invalid PLASO_PROVISIONING_MODEL %q: must be SPOT or STANDARD", cfg.ProvisioningModel)
	}

	var missing []string
	for _, pair := range []struct{ name, val string }{
		{"GOOGLE_CLOUD_PROJECT", cfg.GCPProject},
		{"GCP_REGION", cfg.Region},
		{"CASE_ID", cfg.CaseID},
		{"PLASO_JOB_IMAGE", cfg.PlasoJobImage},
		{"PLASO_JOB_SA", cfg.PlasoJobSA},
		{"SRC_BUCKET", cfg.SrcBucket},
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

func parseInt64Env(name string, def int64) (int64, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return def, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", name, raw, err)
	}
	return v, nil
}
