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

// Package bqload wraps the BigQuery client to submit a load job for a
// single JSON Lines timeline file produced by plaso-job.
package bqload

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/bigquery"
)

// Client wraps *bigquery.Client.
type Client struct {
	inner   *bigquery.Client
	dataset string
	table   string
}

// NewClient creates a BigQuery client scoped to the given dataset/table.
func NewClient(ctx context.Context, project, dataset, table string) (*Client, error) {
	c, err := bigquery.NewClient(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("bigquery.NewClient: %w", err)
	}
	return &Client{inner: c, dataset: dataset, table: table}, nil
}

// Close releases the underlying client.
func (c *Client) Close() error {
	return c.inner.Close()
}

// LoadJSONL asynchronously submits a BigQuery load job to append the specified
// JSON Lines file from GCS into the configured dataset and table.
func (c *Client) LoadJSONL(ctx context.Context, gcsURI, caseID string) (string, error) {
	gcsRef := bigquery.NewGCSReference(gcsURI)
	gcsRef.SourceFormat = bigquery.JSON
	gcsRef.IgnoreUnknownValues = true

	loader := c.inner.Dataset(c.dataset).Table(c.table).LoaderFrom(gcsRef)
	loader.WriteDisposition = bigquery.WriteAppend
	loader.JobID = fmt.Sprintf("plaso-load-%s-%d", sanitizeJobIDPart(caseID), time.Now().UnixNano())

	job, err := loader.Run(ctx)
	if err != nil {
		return "", fmt.Errorf("submitting load job for %s: %w", gcsURI, err)
	}
	return job.ID(), nil
}

// sanitizeJobIDPart strips characters not allowed in BigQuery job IDs.
func sanitizeJobIDPart(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}
