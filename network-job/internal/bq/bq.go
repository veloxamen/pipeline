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

// Package bq loads parsed NetworkEvent rows into BigQuery via a
// streaming Load Job: rows are NDJSON-encoded straight into an io.Pipe
// as they're parsed, so memory use stays flat regardless of file size.
package bq

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"cloud.google.com/go/bigquery"
	"github.com/veloxamen/network-job/internal/parser"
)

// Client wraps *bigquery.Client.
type Client struct {
	inner *bigquery.Client
}

// NewClient creates a BigQuery client using application default
// credentials (the Cloud Run Job's runtime service account).
func NewClient(ctx context.Context, projectID string) (*Client, error) {
	c, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("bigquery.NewClient: %w", err)
	}
	return &Client{inner: c}, nil
}

// Close releases the underlying client.
func (c *Client) Close() error {
	return c.inner.Close()
}

// StreamLoader accepts NetworkEvents one at a time and loads them into a
// BigQuery table via a single Load Job fed by an io.Pipe, so the caller
// never has to buffer the full row set.
type StreamLoader struct {
	pw   *io.PipeWriter
	enc  *json.Encoder
	done chan error
}

// NewStreamLoader starts a Load Job against dataset.table and returns a
// StreamLoader ready to accept rows via WriteEvent. The job runs in the
// background; call Close to finish writing and wait for it to complete.
func (c *Client) NewStreamLoader(ctx context.Context, dataset, table string) *StreamLoader {
	pr, pw := io.Pipe()

	source := bigquery.NewReaderSource(pr)
	source.SourceFormat = bigquery.JSON
	loader := c.inner.Dataset(dataset).Table(table).LoaderFrom(source)
	loader.WriteDisposition = bigquery.WriteAppend

	sl := &StreamLoader{pw: pw, enc: json.NewEncoder(pw), done: make(chan error, 1)}

	go func() {
		job, err := loader.Run(ctx)
		if err != nil {
			pr.CloseWithError(err)
			sl.done <- fmt.Errorf("loader.Run: %w", err)
			return
		}
		status, err := job.Wait(ctx)
		if err != nil {
			sl.done <- fmt.Errorf("job.Wait: %w", err)
			return
		}
		if err := status.Err(); err != nil {
			sl.done <- fmt.Errorf("load job failed: %w", err)
			return
		}
		sl.done <- nil
	}()

	return sl
}

// WriteEvent encodes ev as one NDJSON line into the Load Job's input
// stream.
func (sl *StreamLoader) WriteEvent(ev parser.NetworkEvent) error {
	return sl.enc.Encode(ev)
}

// Close signals that no more rows are coming and waits for the Load Job
// to finish.
func (sl *StreamLoader) Close() error {
	if err := sl.pw.Close(); err != nil {
		return fmt.Errorf("close pipe: %w", err)
	}
	return <-sl.done
}
