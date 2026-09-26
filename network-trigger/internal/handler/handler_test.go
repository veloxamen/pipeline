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

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/veloxamen/network-trigger/internal/config"
)

type fakeExecutor struct {
	called    bool
	srcObject string
	logType   string
}

func (f *fakeExecutor) Execute(ctx context.Context, srcObject, logType string) (string, error) {
	f.called = true
	f.srcObject = srcObject
	f.logType = logType
	return "exec-1", nil
}

func postFinalizeEvent(t *testing.T, h http.Handler, bucket, object string) *httptest.ResponseRecorder {
	t.Helper()
	msg := map[string]any{
		"message": map[string]any{
			"attributes": map[string]string{
				"eventType": "OBJECT_FINALIZE",
				"bucketId":  bucket,
				"objectId":  object,
			},
			"messageId": "m1",
		},
	}
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler_LogPrefix_Dispatches(t *testing.T) {
	exec := &fakeExecutor{}
	cfg := &config.Config{SupportedLogTypes: map[string]bool{"google": true}}
	h := NewNetworkTriggerHandler(exec, cfg)

	rec := postFinalizeEvent(t, h, "my-bucket", "log/google/2026-09-16.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !exec.called {
		t.Fatalf("expected job execution to be triggered")
	}
	if exec.logType != "google" {
		t.Errorf("expected log_type google, got %q", exec.logType)
	}
	if exec.srcObject != "log/google/2026-09-16.json" {
		t.Errorf("unexpected src_object %q", exec.srcObject)
	}
}

func TestHandler_ConfigPrefix_Skipped(t *testing.T) {
	exec := &fakeExecutor{}
	cfg := &config.Config{SupportedLogTypes: map[string]bool{"google": true}}
	h := NewNetworkTriggerHandler(exec, cfg)

	rec := postFinalizeEvent(t, h, "my-bucket", "config/google.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (acked, not retried), got %d", rec.Code)
	}
	if exec.called {
		t.Fatalf("expected config/ objects to never trigger a job execution")
	}
}

func TestHandler_UnsupportedLogType_Skipped(t *testing.T) {
	exec := &fakeExecutor{}
	cfg := &config.Config{SupportedLogTypes: map[string]bool{"google": true}}
	h := NewNetworkTriggerHandler(exec, cfg)

	rec := postFinalizeEvent(t, h, "my-bucket", "log/unknown_vendor/file.json")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if exec.called {
		t.Fatalf("expected unsupported log types to never trigger a job execution")
	}
}

func TestHandler_TopLevelObject_Skipped(t *testing.T) {
	exec := &fakeExecutor{}
	cfg := &config.Config{SupportedLogTypes: map[string]bool{"google": true}}
	h := NewNetworkTriggerHandler(exec, cfg)

	// An object with no "/" at all (e.g. accidentally uploaded to the
	// bucket root) is outside log/ and must be skipped, not panic on
	// the path-splitting logic.
	rec := postFinalizeEvent(t, h, "my-bucket", "README.txt")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if exec.called {
		t.Fatalf("expected top-level objects to never trigger a job execution")
	}
}
