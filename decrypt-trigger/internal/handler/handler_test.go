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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/veloxamen/decrypt-trigger/internal/config"
	"github.com/veloxamen/decrypt-trigger/internal/handler"
)

type stubJobsClient struct {
	called     bool
	lastCaseID string
	lastDevice string
	lastBucket string
	lastObject string
	err        error
}

func (s *stubJobsClient) Execute(_ context.Context, caseID, deviceName, bucket, object string) (string, error) {
	s.called = true
	s.lastCaseID = caseID
	s.lastDevice = deviceName
	s.lastBucket = bucket
	s.lastObject = object
	return "projects/p/locations/r/jobs/j/executions/exec-1", s.err
}

func buildPubSubBody(t *testing.T, bucket, object, eventType string) []byte {
	t.Helper()
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
			"messageId":   "msg-001",
			"publishTime": "2025-01-01T00:00:00Z",
		},
		"subscription": "projects/p/subscriptions/s",
	}
	b, _ := json.Marshal(msg)
	return b
}

func newTestHandler(stub handler.JobExecutor) http.Handler {
	cfg := &config.Config{
		AllowedSrcBucket: "forensic-uploads",
		DstBucket:        "forensic-work",
		KMSKeyName:       "projects/p/locations/r/keyRings/kr/cryptoKeys/k/cryptoKeyVersions/1",
		CaseID:           "vxmn",
	}
	return handler.NewPubSubHandlerWithExecutor(stub, cfg)
}

func TestHandler_ValidArtifact(t *testing.T) {
	stub := &stubJobsClient{}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "forensic-uploads", "cases/case01/host_20250101.vxmn", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !stub.called {
		t.Error("expected job to be kicked, but Execute was not called")
	}
	if stub.lastObject != "cases/case01/host_20250101.vxmn" {
		t.Errorf("unexpected object: %s", stub.lastObject)
	}
	if stub.lastCaseID != "cases" {
		t.Errorf("unexpected case id: %s", stub.lastCaseID)
	}
	if stub.lastDevice != "host_20250101" {
		t.Errorf("unexpected device name: %s", stub.lastDevice)
	}
}

func TestHandler_MissingCaseIDPrefix(t *testing.T) {
	stub := &stubJobsClient{}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "forensic-uploads", "host_20250101.vxmn", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if stub.called {
		t.Error("job should NOT be kicked when object has no case-id prefix")
	}
}

func TestHandler_NonFinalizeEvent(t *testing.T) {
	stub := &stubJobsClient{}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "forensic-uploads", "host.vxmn", "OBJECT_DELETE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if stub.called {
		t.Error("job should NOT be kicked for non-finalize events")
	}
}

func TestHandler_WrongBucket(t *testing.T) {
	stub := &stubJobsClient{}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "other-bucket", "host.vxmn", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if stub.called {
		t.Error("job should NOT be kicked for disallowed bucket")
	}
}

func TestHandler_NotArtifactFile(t *testing.T) {
	stub := &stubJobsClient{}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "forensic-uploads", "readme.txt", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if stub.called {
		t.Error("job should NOT be kicked for non-artifact files")
	}
}

func TestHandler_JobFailureReturns500(t *testing.T) {
	stub := &stubJobsClient{err: errJobFailed}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "forensic-uploads", "Case001/host.vxmn", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on job failure, got %d", rec.Code)
	}
}

var errJobFailed = fmt.Errorf("simulated job failure")
