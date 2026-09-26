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
// notifications carrying GCS Object Finalize events.
package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path"

	"github.com/veloxamen/plaso-trigger/internal/config"
)

type pubSubMessage struct {
	Message struct {
		Data       string            `json:"data"`
		Attributes map[string]string `json:"attributes"`
		MessageID  string            `json:"messageId"`
	} `json:"message"`
}

const completionMarkerName = "_READY"

// JobExecutor is the interface used to kick off plaso-job.
type JobExecutor interface {
	Execute(ctx context.Context, caseID string) (string, error)
}

// PlasoTriggerHandler handles Pub/Sub push HTTP requests.
type PlasoTriggerHandler struct {
	jobs JobExecutor
	cfg  *config.Config
}

// NewPlasoTriggerHandler constructs a PlasoTriggerHandler.
func NewPlasoTriggerHandler(jobs JobExecutor, cfg *config.Config) *PlasoTriggerHandler {
	return &PlasoTriggerHandler{jobs: jobs, cfg: cfg}
}

func (h *PlasoTriggerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
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

	if path.Base(object) != completionMarkerName {
		log.Info("object is not a decrypt-completion marker, skipping")
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID := h.cfg.CaseID

	execName, err := h.jobs.Execute(r.Context(), caseID)
	if err != nil {
		log.Error("plaso-job execution failed", "error", err)
		http.Error(w, "job execution failed", http.StatusInternalServerError)
		return
	}

	log.Info("plaso-job execution submitted", "execution", execName, "case_id", caseID)
	w.WriteHeader(http.StatusOK)
}
