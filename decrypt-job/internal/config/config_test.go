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

package config

import "testing"

// setRequiredEnv sets the env vars Load() requires, using t.Setenv so each
// var is automatically restored after the test.
func setRequiredEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	base := map[string]string{
		"SRC_BUCKET":   "vxmn-2026001-in",
		"SRC_OBJECT":   "SERVER01.2026001",
		"CASE_ID":      "2026001",
		"DST_BUCKET":   "vxmn-2026001-work",
		"KMS_KEY_NAME": "projects/p/locations/r/keyRings/kr/cryptoKeys/k/cryptoKeyVersions/1",
	}
	for k, v := range overrides {
		base[k] = v
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
}

func TestLoad_FlatObjectMatchingExtension(t *testing.T) {
	setRequiredEnv(t, nil)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CaseID != "2026001" {
		t.Errorf("CaseID = %q, want %q", cfg.CaseID, "2026001")
	}
}

func TestLoad_ExtensionMismatchFailsClosed(t *testing.T) {
	setRequiredEnv(t, map[string]string{
		"SRC_OBJECT": "SERVER01.2025999",
		"CASE_ID":    "2026001",
	})

	if _, err := Load(); err == nil {
		t.Fatal("expected error for mismatched CASE_ID/extension, got nil")
	}
}

func TestLoad_ExtensionMismatchAllowedOverride(t *testing.T) {
	setRequiredEnv(t, map[string]string{
		"SRC_OBJECT":             "SERVER01.2025999",
		"CASE_ID":                "2026001",
		"ALLOW_CASE_ID_MISMATCH": "true",
	})

	if _, err := Load(); err != nil {
		t.Fatalf("unexpected error with ALLOW_CASE_ID_MISMATCH=true: %v", err)
	}
}

func TestLoad_NoLongerRequiresPathPrefix(t *testing.T) {
	setRequiredEnv(t, map[string]string{
		"SRC_OBJECT": "SERVER01.2026001",
	})

	if _, err := Load(); err != nil {
		t.Fatalf("flat object name should not require a case-id path prefix: %v", err)
	}
}

func TestLoad_MissingRequiredVar(t *testing.T) {
	setRequiredEnv(t, map[string]string{"SRC_BUCKET": ""})

	if _, err := Load(); err == nil {
		t.Fatal("expected error for missing SRC_BUCKET, got nil")
	}
}
