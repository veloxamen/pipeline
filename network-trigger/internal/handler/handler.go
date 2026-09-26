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
	"strings"

	"github.com/veloxamen/network-trigger/internal/config"
)

type pubSubMessage struct {
	Message struct {
		Data       string            `json:"data"`
		Attributes map[string]string `json:"attributes"`
		MessageID  string            `json:"messageId"`
	} `json:"message"`
}

// JobExecutor defines the interface used to kick off network-job.
type JobExecutor interface {
	Execute(ctx context.Context, srcObject, logType string) (string, error)
}

// NetworkTriggerHandler handles Pub/Sub push HTTP requests.
type NetworkTriggerHandler struct {
	jobs JobExecutor
	cfg  *config.Config
}

// NewNetworkTriggerHandler constructs a NetworkTriggerHandler.
func NewNetworkTriggerHandler(jobs JobExecutor, cfg *config.Config) *NetworkTriggerHandler {
	return &NetworkTriggerHandler{jobs: jobs, cfg: cfg}
}

func (h *NetworkTriggerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	// Only objects under log/ are treated as ingestable log files.
	// Everything else — most notably config/<log_type>.json mapping
	// files written to the same bucket — is silently skipped here. This
	// is expected, routine traffic (not a misconfiguration), so it's
	// logged at Info level and acknowledged with 200 either way to avoid
	// Pub/Sub redelivery storms.
	rest, ok := strings.CutPrefix(object, "log/")
	if !ok {
		log.Info("object is outside the log/ prefix, skipping", "expected_format", "log/<log_type>/<filename>")
		w.WriteHeader(http.StatusOK)
		return
	}

	logType, _, ok := strings.Cut(rest, "/")
	if !ok || logType == "" {
		log.Error("object has no log-type path segment under log/, skipping",
			"expected_format", "log/<log_type>/<filename>")
		w.WriteHeader(http.StatusOK)
		return
	}

	if !h.cfg.SupportedLogTypes[logType] {
		log.Error("unsupported log type, skipping", "log_type", logType)
		w.WriteHeader(http.StatusOK)
		return
	}

	execName, err := h.jobs.Execute(r.Context(), object, logType)
	if err != nil {
		log.Error("network-job execution failed", "error", err)
		http.Error(w, "job execution failed", http.StatusInternalServerError)
		return
	}

	log.Info("network-job execution submitted", "execution", execName, "log_type", logType)
	w.WriteHeader(http.StatusOK)
}
