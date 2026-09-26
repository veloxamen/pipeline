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

// Config holds all runtime parameters for the Pub/Sub subscriber.
type Config struct {
	// Port is the HTTP port the subscriber listens on (default: 8080).
	Port string

	// GCPProject is the Google Cloud project ID.
	GCPProject string
	// GCPRegion is the Cloud Run Jobs deployment region.
	GCPRegion string

	// DecryptJobName is the Cloud Run Jobs job name to execute for decryption.
	DecryptJobName string

	// DstBucket is passed to the decrypt job as DST_BUCKET.
	DstBucket string
	// DstPrefix is an optional output path prefix passed to the decrypt job.
	DstPrefix string

	// KMSKeyName is the fully qualified Cloud KMS key version name.
	KMSKeyName string

	// AllowedSrcBucket restricts processing to a specific source bucket.
	AllowedSrcBucket string

	// CaseID is this deployment's case identifier and expected artifact file extension.
	CaseID string

	// PubSubAudience is used to validate the OIDC token from Pub/Sub push.
	PubSubAudience string
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
		GCPRegion:        os.Getenv("GCP_REGION"),
		DecryptJobName:   os.Getenv("DECRYPT_JOB_NAME"),
		DstBucket:        os.Getenv("DST_BUCKET"),
		DstPrefix:        os.Getenv("DST_PREFIX"),
		KMSKeyName:       os.Getenv("KMS_KEY_NAME"),
		AllowedSrcBucket: os.Getenv("ALLOWED_SRC_BUCKET"),
		CaseID:           os.Getenv("CASE_ID"),
		PubSubAudience:   os.Getenv("PUBSUB_AUDIENCE"),
	}

	var missing []string
	for _, pair := range []struct{ name, val string }{
		{"GOOGLE_CLOUD_PROJECT", cfg.GCPProject},
		{"GCP_REGION", cfg.GCPRegion},
		{"DECRYPT_JOB_NAME", cfg.DecryptJobName},
		{"DST_BUCKET", cfg.DstBucket},
		{"KMS_KEY_NAME", cfg.KMSKeyName},
		{"CASE_ID", cfg.CaseID},
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
