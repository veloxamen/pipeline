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

// Package main implements a Pub/Sub push subscriber that triggers Plaso job executions.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/veloxamen/plaso-trigger/internal/config"
	"github.com/veloxamen/plaso-trigger/internal/handler"
	"github.com/veloxamen/plaso-trigger/internal/jobs"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load failed", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	jobsClient, err := jobs.NewClient(ctx, cfg)
	if err != nil {
		slog.Error("jobs client init failed", "error", err)
		os.Exit(1)
	}
	defer jobsClient.Close()

	mux := http.NewServeMux()
	mux.Handle("/", handler.NewPlasoTriggerHandler(jobsClient, cfg))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	slog.Info("plaso-trigger listening", "port", cfg.Port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
