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

// Package main is the entry point for the Cloud Run Jobs network log
// ingestion job. It streams one raw log object from GCS through a
// LOG_TYPE-selected parser into a BigQuery Load Job. LOG_TYPE resolves
// to a parser in one of two ways: a handful of vendors (fortigate,
// generic_csv, cisco_asa) are built-in Go parsers (internal/parser); any
// other LOG_TYPE is expected to have a field-mapping config at
// gs://<SrcBucket>/config/<LOG_TYPE>.json (internal/mapping), describing
// how to extract NetworkEvent columns from that vendor's JSON, KV, or
// CSV log format — no Go code needed to onboard a new vendor. If the
// object is a zip, gz, tar.gz, or tgz archive, internal/archive
// transparently decompresses it (recursively, for nested archives) and
// every raw file found inside is parsed the same way. Plain files are
// still streamed straight through with no buffering; only zip archives
// require buffering to local disk first, since zip needs random access
// that a streaming GCS reader can't provide (see internal/archive).

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/veloxamen/network-job/internal/archive"
	"github.com/veloxamen/network-job/internal/bq"
	"github.com/veloxamen/network-job/internal/config"
	"github.com/veloxamen/network-job/internal/gcs"
	"github.com/veloxamen/network-job/internal/mapping"
	"github.com/veloxamen/network-job/internal/parser"
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
		slog.Error("network job failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config.Config) error {
	slog.Info("starting network job",
		"src_bucket", cfg.SrcBucket,
		"src_object", cfg.SrcObject,
		"log_type", cfg.LogType,
	)

	gcsClient, err := gcs.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("gcs.NewClient: %w", err)
	}
	defer gcsClient.Close()

	p, ok := parser.Lookup(cfg.LogType)
	if !ok {
		// Not a built-in parser — fall back to an externally configured
		// mapping (config/<LOG_TYPE>.json in the same bucket). Any
		// failure here is fatal and fails the job clearly, rather than
		// silently skipping the file: there is no third fallback.
		p, err = loadMappingParser(ctx, gcsClient, cfg)
		if err != nil {
			return fmt.Errorf("no built-in parser for log type %q, and loading its mapping config failed: %w", cfg.LogType, err)
		}
	}

	return runWithParser(ctx, cfg, gcsClient, p)
}

// loadMappingParser reads gs://<SrcBucket>/<MappingConfigObject>,
// parses it as a mapping.Config, and builds the corresponding
// JSON/KV/CSV parser.
func loadMappingParser(ctx context.Context, gcsClient *gcs.Client, cfg *config.Config) (parser.Parser, error) {
	slog.Info("loading mapping config", "object", cfg.MappingConfigObject)

	r, err := gcsClient.OpenObject(ctx, cfg.SrcBucket, cfg.MappingConfigObject)
	if err != nil {
		return nil, fmt.Errorf("opening gs://%s/%s: %w", cfg.SrcBucket, cfg.MappingConfigObject, err)
	}
	defer r.Close()

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading gs://%s/%s: %w", cfg.SrcBucket, cfg.MappingConfigObject, err)
	}

	mcfg, err := mapping.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parsing gs://%s/%s: %w", cfg.SrcBucket, cfg.MappingConfigObject, err)
	}

	return parser.NewMappingParser(mcfg)
}

func runWithParser(ctx context.Context, cfg *config.Config, gcsClient *gcs.Client, p parser.Parser) error {
	src, err := gcsClient.OpenObject(ctx, cfg.SrcBucket, cfg.SrcObject)
	if err != nil {
		return fmt.Errorf("opening gs://%s/%s: %w", cfg.SrcBucket, cfg.SrcObject, err)
	}
	defer src.Close()

	bqClient, err := bq.NewClient(ctx, cfg.GCPProject)
	if err != nil {
		return fmt.Errorf("bq.NewClient: %w", err)
	}
	defer bqClient.Close()

	loader := bqClient.NewStreamLoader(ctx, cfg.BQDataset, cfg.BQTable)

	var eventCount, errorCount, fileCount int
	emit := func(ev parser.NetworkEvent) error {
		eventCount++
		return loader.WriteEvent(ev)
	}
	onRowError := func(re parser.RowError) {
		errorCount++
		slog.Error("skipping unparsable row", "line", re.LineNumber, "content", re.Line, "error", re.Err)
	}

	// SRC_OBJECT may itself be a raw log file, or a zip/gz/tar.gz/tgz
	// archive bundling one or more raw log files — archive.Walk
	// transparently unwraps any nesting of those and calls handle once
	// per raw file found, all parsed by the same LOG_TYPE parser and
	// loaded into the same BigQuery Load Job.
	handle := func(_ context.Context, name string, r io.Reader) error {
		fileCount++
		slog.Info("parsing file", "name", name)
		return p.Parse(r, emit, onRowError)
	}
	parseErr := archive.Walk(ctx, cfg.SrcObject, src, handle)

	loadErr := loader.Close()

	if parseErr != nil {
		return fmt.Errorf("parse: %w", parseErr)
	}
	if loadErr != nil {
		return fmt.Errorf("LoadEvents: %w", loadErr)
	}

	slog.Info("network job completed successfully",
		"src_object", cfg.SrcObject,
		"files_parsed", fileCount,
		"events_loaded", eventCount,
		"rows_skipped", errorCount,
	)
	return nil
}
