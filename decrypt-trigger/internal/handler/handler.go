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

// Package handler implements the HTTP handler for Pub/Sub push notifications.
//
// Pub/Sub push delivers messages as HTTP POST with JSON body:
//
//	{
//	  "message": {
//	    "data": "<base64-encoded GCS object metadata>",
//	    "attributes": {
//	      "eventType": "OBJECT_FINALIZE",
//	      "bucketId": "...",
//	      "objectId": "...",
//	      ...
//	    },
//	    "messageId": "...",
//	    "publishTime": "..."
//	  },
//	  "subscription": "projects/.../subscriptions/..."
//	}
//
// IMPORTANT: eventType, bucketId, and objectId are Pub/Sub message
// attributes, not fields inside the base64-encoded data payload.
package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/veloxamen/decrypt-trigger/internal/config"
	"github.com/veloxamen/decrypt-trigger/internal/jobs"
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

// JobExecutor is the interface used to kick a Cloud Run Job execution.
type JobExecutor interface {
	Execute(ctx context.Context, caseID, deviceName, srcBucket, srcObject string) (string, error)
}

// PubSubHandler handles Pub/Sub push HTTP requests.
type PubSubHandler struct {
	jobs JobExecutor
	cfg  *config.Config
}

// NewPubSubHandler constructs a PubSubHandler backed by a real jobs.Client.
func NewPubSubHandler(j *jobs.Client, cfg *config.Config) *PubSubHandler {
	return &PubSubHandler{jobs: j, cfg: cfg}
}

// NewPubSubHandlerWithExecutor constructs a PubSubHandler with a custom JobExecutor.
func NewPubSubHandlerWithExecutor(j JobExecutor, cfg *config.Config) *PubSubHandler {
	return &PubSubHandler{jobs: j, cfg: cfg}
}

func (h *PubSubHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	if !isEncryptedArtifact(object, h.cfg.CaseID) {
		log.Info("object does not match artifact pattern, skipping",
			"expected_extension", h.cfg.CaseID)
		w.WriteHeader(http.StatusOK)
		return
	}

	caseID := h.cfg.CaseID
	deviceName := deviceNameFromObject(object)

	execName, err := h.jobs.Execute(r.Context(), caseID, deviceName, bucket, object)
	if err != nil {
		log.Error("job execution failed", "error", err)
		http.Error(w, "job execution failed", http.StatusInternalServerError)
		return
	}

	log.Info("job kicked successfully", "execution", execName)
	w.WriteHeader(http.StatusOK)
}

// isEncryptedArtifact returns true if the object name looks like an encrypted artifact.
func isEncryptedArtifact(name, caseID string) bool {
	return strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(caseID))
}

// deviceNameFromObject derives a device name from the object path.
func deviceNameFromObject(rest string) string {
	base := rest
	if idx := strings.LastIndex(base, "/"); idx != -1 {
		base = base[idx+1:]
	}
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" {
		return "unknown"
	}
	return base
}
