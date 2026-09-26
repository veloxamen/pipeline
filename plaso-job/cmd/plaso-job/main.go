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

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/veloxamen/plaso-job/internal/config"
	"github.com/veloxamen/plaso-job/internal/gcs"
	"github.com/veloxamen/plaso-job/internal/psteal"
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
	if err := run(ctx, cfg); err != nil {
		slog.Error("plaso job failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config.Config) error {
	slog.Info("starting plaso job",
		"case_id", cfg.CaseID,
		"src_bucket", cfg.SrcBucket,
		"dst_bucket", cfg.DstBucket,
	)

	if err := resetWorkDir(cfg.WorkDir); err != nil {
		return fmt.Errorf("resetting work dir %s: %w", cfg.WorkDir, err)
	}

	gcsClient, err := gcs.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("gcs.NewClient: %w", err)
	}
	defer gcsClient.Close()

	inputDir := filepath.Join(cfg.WorkDir, "input")
	if err := os.MkdirAll(inputDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", inputDir, err)
	}

	srcPrefix := cfg.SrcPrefix
	displaySrc := fmt.Sprintf("gs://%s/", cfg.SrcBucket)
	if srcPrefix != "" {
		displaySrc = fmt.Sprintf("gs://%s/%s/", cfg.SrcBucket, strings.Trim(srcPrefix, "/"))
	}

	slog.Info("downloading case evidence", "src", displaySrc)
	n, err := gcsClient.DownloadPrefix(ctx, cfg.SrcBucket, srcPrefix, inputDir)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", displaySrc, err)
	}
	if n == 0 {
		return fmt.Errorf("no objects found under %s", displaySrc)
	}
	slog.Info("downloaded evidence files", "count", n)

	rawOutput := filepath.Join(cfg.WorkDir, "raw_timeline.jsonl")
	slog.Info("running psteal", "source", inputDir, "output", rawOutput)
	if err := psteal.Run(ctx, cfg.PstealBin, inputDir, rawOutput); err != nil {
		return fmt.Errorf("psteal.Run: %w", err)
	}

	if err := os.RemoveAll(inputDir); err != nil {
		slog.Warn("failed to remove input evidence", "dir", inputDir, "error", err)
	}

	finalOutput := filepath.Join(cfg.WorkDir, "timeline.jsonl")
	errorLinesOutput := filepath.Join(cfg.WorkDir, "error_lines.jsonl")
	eventCount, skippedCount, err := psteal.PostProcess(rawOutput, finalOutput, errorLinesOutput, inputDir, "unknown")
	if err != nil {
		return fmt.Errorf("psteal.PostProcess: %w", err)
	}
	slog.Info("post-processed events", "count", eventCount, "skipped_oversized", skippedCount)

	if err := os.Remove(rawOutput); err != nil {
		slog.Warn("failed to remove raw timeline", "path", rawOutput, "error", err)
	}

	runStamp := time.Now().UTC().Format("20060102T150405Z")

	dstObjectName := fmt.Sprintf("%s-timeline-%s.jsonl", cfg.CaseID, runStamp)
	dstObject := dstObjectName
	if cfg.DstPrefix != "" {
		dstObject = strings.Trim(cfg.DstPrefix, "/") + "/" + dstObjectName
	}

	slog.Info("uploading timeline", "dst", fmt.Sprintf("gs://%s/%s", cfg.DstBucket, dstObject))
	if err := gcsClient.UploadFile(ctx, cfg.DstBucket, dstObject, finalOutput); err != nil {
		return fmt.Errorf("uploading timeline: %w", err)
	}

	// Note the "-errorlines-" naming deliberately avoids the "-timeline-"
	// substring bqload-trigger keys off of (see isTimelineFile/strings.Cut
	// in bqload-trigger/internal/handler/handler.go), so this upload won't
	// get picked up and pointed at the timeline_events load path — it's a
	// separate side-artifact for manual review / a future dedicated
	// error_lines BigQuery table, not part of the timeline_events schema.
	if skippedCount > 0 {
		errObjectName := fmt.Sprintf("%s-errorlines-%s.jsonl", cfg.CaseID, runStamp)
		errObject := errObjectName
		if cfg.DstPrefix != "" {
			errObject = strings.Trim(cfg.DstPrefix, "/") + "/" + errObjectName
		}
		slog.Warn("oversized events skipped during this run, summaries uploaded for review",
			"count", skippedCount,
			"dst", fmt.Sprintf("gs://%s/%s", cfg.DstBucket, errObject),
		)
		if err := gcsClient.UploadFile(ctx, cfg.DstBucket, errObject, errorLinesOutput); err != nil {
			slog.Warn("failed to upload error-lines summary", "path", errorLinesOutput, "error", err)
		}
	}

	if err := os.Remove(errorLinesOutput); err != nil {
		slog.Warn("failed to remove error-lines file", "path", errorLinesOutput, "error", err)
	}

	slog.Info("plaso job completed successfully",
		"case_id", cfg.CaseID,
		"events", eventCount,
		"skipped_oversized", skippedCount,
		"output", fmt.Sprintf("gs://%s/%s", cfg.DstBucket, dstObject),
	)
	return nil
}

func resetWorkDir(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("removing %s: %w", dir, err)
	}
	return os.MkdirAll(dir, 0o755)
}
