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

// Package handler implements the HTTP handler for Pub/Sub push
// notifications carrying GCS Object Finalize events from plaso-job's
// output bucket ($BUCKET_OUTPUT).
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/veloxamen/bqload-trigger/internal/config"
)

// pubSubMessage is the outer envelope sent by Pub/Sub push.
type pubSubMessage struct {
	Message struct {
		Data        string            `json:"data"`
		Attributes  map[string]string `json:"attributes"`
		MessageID   string            `json:"messageId"`
		PublishTime string            `json:"publishTime"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// BQLoader is the interface used to submit a BigQuery load job. Abstracted
// for testability.
type BQLoader interface {
	LoadJSONL(ctx context.Context, gcsURI, caseID string) (string, error)
}

// BQLoadHandler handles Pub/Sub push HTTP requests.
type BQLoadHandler struct {
	loader BQLoader
	cfg    *config.Config
}

// NewBQLoadHandler constructs a BQLoadHandler.
func NewBQLoadHandler(loader BQLoader, cfg *config.Config) *BQLoadHandler {
	return &BQLoadHandler{loader: loader, cfg: cfg}
}

func (h *BQLoadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
	if err != nil {
		slog.Error("read body failed", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var msg pubSubMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		slog.Error("json unmarshal failed", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	eventType := msg.Message.Attributes["eventType"]
	bucket := msg.Message.Attributes["bucketId"]
	object := msg.Message.Attributes["objectId"]

	log := slog.With(
		"bucket", bucket,
		"object", object,
		"messageId", msg.Message.MessageID,
	)

	// --- Validation ---

	if eventType != "OBJECT_FINALIZE" {
		log.Info("skipping non-finalize event", "eventType", eventType)
		w.WriteHeader(http.StatusOK)
		return
	}

	if h.cfg.AllowedSrcBucket != "" && bucket != h.cfg.AllowedSrcBucket {
		log.Warn("bucket not allowed, skipping", "allowed", h.cfg.AllowedSrcBucket)
		w.WriteHeader(http.StatusOK)
		return
	}

	if !isTimelineFile(object) {
		log.Info("object does not match timeline file pattern, skipping")
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID, _, ok := strings.Cut(object, "-timeline-")
	if !ok || caseID == "" {
		log.Error("object has no case-id filename prefix, skipping",
			"expected_format", "<case_id>-timeline-<timestamp>.jsonl")
		w.WriteHeader(http.StatusOK)
		return
	}

	gcsURI := fmt.Sprintf("gs://%s/%s", bucket, object)
	jobID, err := h.loader.LoadJSONL(r.Context(), gcsURI, caseID)
	if err != nil {
		log.Error("bigquery load submission failed", "error", err)
		http.Error(w, "load job submission failed", http.StatusInternalServerError)
		return
	}

	log.Info("bigquery load job submitted", "job_id", jobID, "case_id", caseID)
	w.WriteHeader(http.StatusOK)
}

// isTimelineFile returns true if the object name looks like a plaso-job
// timeline output file.
func isTimelineFile(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".jsonl")
}
