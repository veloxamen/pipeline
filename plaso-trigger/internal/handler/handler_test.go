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

package handler_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/veloxamen/plaso-trigger/internal/config"
	"github.com/veloxamen/plaso-trigger/internal/handler"
)

type stubJobsClient struct {
	called     bool
	lastCaseID string
	err        error
}

func (s *stubJobsClient) Execute(_ context.Context, caseID string) (string, error) {
	s.called = true
	s.lastCaseID = caseID
	return "projects/p/locations/r/jobs/plaso-job/executions/exec-1", s.err
}

func buildPubSubBody(bucket, object, eventType string) []byte {
	notif := map[string]string{
		"bucket": bucket,
		"name":   object,
	}
	notifJSON, _ := json.Marshal(notif)
	encoded := base64.StdEncoding.EncodeToString(notifJSON)

	msg := map[string]interface{}{
		"message": map[string]interface{}{
			"data": encoded,
			"attributes": map[string]string{
				"eventType": eventType,
				"bucketId":  bucket,
				"objectId":  object,
			},
			"messageId": "msg-001",
		},
	}
	b, _ := json.Marshal(msg)
	return b
}

func newTestHandler(stub handler.JobExecutor) http.Handler {
	cfg := &config.Config{
		AllowedSrcBucket: "forensic-work",
		GCPProject:       "p",
		Region:           "r",
		PlasoJobName:     "plaso-job",
		CaseID:           "2026001",
	}
	return handler.NewPlasoTriggerHandler(stub, cfg)
}

func TestHandler_MarkerTriggersJob(t *testing.T) {
	stub := &stubJobsClient{}
	h := newTestHandler(stub)

	body := buildPubSubBody("forensic-work", "SERVER01/_READY", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !stub.called {
		t.Fatal("expected plaso-job to be triggered")
	}
	if stub.lastCaseID != "2026001" {
		t.Errorf("unexpected case id: %s", stub.lastCaseID)
	}
}

func TestHandler_NonMarkerObjectSkipped(t *testing.T) {
	stub := &stubJobsClient{}
	h := newTestHandler(stub)

	body := buildPubSubBody("forensic-work", "SERVER01/Windows/System32/config/SYSTEM", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if stub.called {
		t.Error("plaso-job should NOT be triggered for non-marker objects")
	}
}

func TestHandler_NonFinalizeEvent(t *testing.T) {
	stub := &stubJobsClient{}
	h := newTestHandler(stub)

	body := buildPubSubBody("forensic-work", "SERVER01/_READY", "OBJECT_DELETE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if stub.called {
		t.Error("plaso-job should NOT be triggered for non-finalize events")
	}
}

func TestHandler_WrongBucket(t *testing.T) {
	stub := &stubJobsClient{}
	h := newTestHandler(stub)

	body := buildPubSubBody("other-bucket", "SERVER01/_READY", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if stub.called {
		t.Error("plaso-job should NOT be triggered for disallowed bucket")
	}
}

// TestHandler_MarkerAtBucketRoot confirms that even a completion marker
// with no subdirectory at all still triggers correctly.
func TestHandler_MarkerAtBucketRoot(t *testing.T) {
	stub := &stubJobsClient{}
	h := newTestHandler(stub)

	body := buildPubSubBody("forensic-work", completionMarkerNameForTest, "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if !stub.called {
		t.Fatal("expected plaso-job to be triggered even with no path prefix")
	}
	if stub.lastCaseID != "2026001" {
		t.Errorf("unexpected case id: %s", stub.lastCaseID)
	}
}

const completionMarkerNameForTest = "_READY"

func TestHandler_JobFailureReturns500(t *testing.T) {
	stub := &stubJobsClient{err: errors.New("simulated run job failure")}
	h := newTestHandler(stub)

	body := buildPubSubBody("forensic-work", "SERVER01/_READY", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}
