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

// Package main is the entry point for the Cloud Run Jobs decryption job.
// It reads an encrypted artifact file from GCS, decrypts it using Cloud KMS
// (RSA-OAEP) for the DEK and AES-256-GCM for the payload, then writes the
// recovered entries to a destination GCS bucket.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/veloxamen/decrypt-job/internal/config"
	"github.com/veloxamen/decrypt-job/internal/decrypt"
	"github.com/veloxamen/decrypt-job/internal/gcs"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("job failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}

	slog.Info("starting decrypt job",
		"case_id", cfg.CaseID,
		"src_bucket", cfg.SrcBucket,
		"src_object", cfg.SrcObject,
		"dst_bucket", cfg.DstBucket,
		"kms_key", cfg.KMSKeyName,
	)

	gcsClient, err := gcs.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("gcs client: %w", err)
	}
	defer gcsClient.Close()

	decryptor, err := decrypt.NewDecryptor(ctx, cfg.KMSKeyName)
	if err != nil {
		return fmt.Errorf("decryptor init: %w", err)
	}
	defer decryptor.Close()

	job := &decrypt.Job{
		GCS:       gcsClient,
		Decryptor: decryptor,
		Cfg:       cfg,
	}

	stats, err := job.Run(ctx)
	if err != nil {
		return fmt.Errorf("job run: %w", err)
	}

	slog.Info("job completed",
		"entries_written", stats.EntriesWritten,
		"bytes_decrypted", stats.BytesDecrypted,
		"elapsed_sec", stats.Elapsed.Seconds(),
	)
	return nil
}
