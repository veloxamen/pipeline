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

	"github.com/veloxamen/bqload-trigger/internal/config"
	"github.com/veloxamen/bqload-trigger/internal/handler"
)

type stubLoader struct {
	called     bool
	lastURI    string
	lastCaseID string
	err        error
}

func (s *stubLoader) LoadJSONL(_ context.Context, gcsURI, caseID string) (string, error) {
	s.called = true
	s.lastURI = gcsURI
	s.lastCaseID = caseID
	return "job-123", s.err
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

func newTestHandler(stub handler.BQLoader) http.Handler {
	cfg := &config.Config{
		AllowedSrcBucket: "forensic-out",
		GCPProject:       "p",
		BQDataset:        "vxmn_dfir",
		BQTable:          "timeline",
	}
	return handler.NewBQLoadHandler(stub, cfg)
}

func TestHandler_ValidTimelineFile(t *testing.T) {
	stub := &stubLoader{}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "forensic-out", "Case001-timeline-20260730T070000Z.jsonl", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !stub.called {
		t.Fatal("expected load job to be submitted, but LoadJSONL was not called")
	}
	if stub.lastURI != "gs://forensic-out/Case001-timeline-20260730T070000Z.jsonl" {
		t.Errorf("unexpected gcs uri: %s", stub.lastURI)
	}
	if stub.lastCaseID != "Case001" {
		t.Errorf("unexpected case id: %s", stub.lastCaseID)
	}
}

func TestHandler_NonFinalizeEvent(t *testing.T) {
	stub := &stubLoader{}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "forensic-out", "Case001-timeline-20260730T070000Z.jsonl", "OBJECT_DELETE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if stub.called {
		t.Error("load job should NOT be submitted for non-finalize events")
	}
}

func TestHandler_WrongBucket(t *testing.T) {
	stub := &stubLoader{}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "other-bucket", "Case001-timeline-20260730T070000Z.jsonl", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if stub.called {
		t.Error("load job should NOT be submitted for disallowed bucket")
	}
}

func TestHandler_NotTimelineFile(t *testing.T) {
	stub := &stubLoader{}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "forensic-out", "Case001-readme.txt", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if stub.called {
		t.Error("load job should NOT be submitted for non-.jsonl files")
	}
}

func TestHandler_MissingCaseIDPrefix(t *testing.T) {
	stub := &stubLoader{}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "forensic-out", "timeline-20260730T070000Z.jsonl", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if stub.called {
		t.Error("load job should NOT be submitted when object has no case-id prefix")
	}
}

func TestHandler_LoadFailureReturns500(t *testing.T) {
	stub := &stubLoader{err: errors.New("simulated bigquery error")}
	h := newTestHandler(stub)

	body := buildPubSubBody(t, "forensic-out", "Case001-timeline-20260730T070000Z.jsonl", "OBJECT_FINALIZE")
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on load failure, got %d", rec.Code)
	}
}
