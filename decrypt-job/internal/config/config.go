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
	"strings"
)

// Config holds all runtime parameters for the decryption job.
type Config struct {
	// SrcBucket is the GCS bucket containing the encrypted file.
	SrcBucket string
	// SrcObject is the GCS object name of the encrypted file.
	SrcObject string
	// CaseID identifies the forensic case this artifact belongs to.
	CaseID string
	// DstBucket is the GCS bucket to write decrypted entries into.
	DstBucket string
	// DstPrefix is an optional additional path prefix for the output objects.
	DstPrefix string
	// AllowCaseIDMismatch disables the sanity check between CaseID and SrcObject's extension.
	AllowCaseIDMismatch bool
	// KMSKeyName is the full Cloud KMS key version resource name used to decrypt the DEK.
	KMSKeyName string
	// GCPProject is used for Cloud KMS API calls when the key name does not embed the project.
	GCPProject string
}

// Load reads configuration from environment variables and validates that all
// required fields are present.
func Load() (*Config, error) {
	cfg := &Config{
		SrcBucket:           os.Getenv("SRC_BUCKET"),
		SrcObject:           os.Getenv("SRC_OBJECT"),
		CaseID:              os.Getenv("CASE_ID"),
		DstBucket:           os.Getenv("DST_BUCKET"),
		DstPrefix:           os.Getenv("DST_PREFIX"),
		AllowCaseIDMismatch: os.Getenv("ALLOW_CASE_ID_MISMATCH") == "true",
		KMSKeyName:          os.Getenv("KMS_KEY_NAME"),
		GCPProject:          os.Getenv("GOOGLE_CLOUD_PROJECT"),
	}

	var missing []string
	for _, pair := range []struct{ name, val string }{
		{"SRC_BUCKET", cfg.SrcBucket},
		{"SRC_OBJECT", cfg.SrcObject},
		{"CASE_ID", cfg.CaseID},
		{"DST_BUCKET", cfg.DstBucket},
		{"KMS_KEY_NAME", cfg.KMSKeyName},
	} {
		if pair.val == "" {
			missing = append(missing, pair.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}

	if err := cfg.validateCaseID(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validateCaseID checks that SrcObject's extension matches CaseID.
func (c *Config) validateCaseID() error {
	ext := "." + c.CaseID
	if !strings.HasSuffix(strings.ToLower(c.SrcObject), strings.ToLower(ext)) {
		if c.AllowCaseIDMismatch {
			return nil
		}
		return fmt.Errorf("case ID mismatch: CASE_ID=%q but SRC_OBJECT %q does not end in %q (set ALLOW_CASE_ID_MISMATCH=true to override)", c.CaseID, c.SrcObject, ext)
	}
	return nil
}
