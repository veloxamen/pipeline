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

// Package gcs wraps the Google Cloud Storage client with the operations
// needed by the decrypt job: streaming read and streaming write.
package gcs

import (
	"context"
	"fmt"
	"io"

	storage "cloud.google.com/go/storage"
)

// Client wraps *storage.Client with convenience methods.
type Client struct {
	inner *storage.Client
}

// NewClient creates a GCS client using Application Default Credentials.
func NewClient(ctx context.Context) (*Client, error) {
	c, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage.NewClient: %w", err)
	}
	return &Client{inner: c}, nil
}

// Close releases the underlying GCS connection.
func (c *Client) Close() error {
	return c.inner.Close()
}

// NewReader opens a GCS object for streaming read.
func (c *Client) NewReader(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
	rc, err := c.inner.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("open gs://%s/%s: %w", bucket, object, err)
	}
	return rc, nil
}

// Upload streams data from r to GCS and returns the number of bytes written.
func (c *Client) Upload(ctx context.Context, bucket, object string, r io.Reader) (int64, error) {
	wc := c.inner.Bucket(bucket).Object(object).NewWriter(ctx)
	wc.ChunkSize = 8 * 1024 * 1024

	n, err := io.Copy(wc, r)
	if err != nil {
		_ = wc.Close()
		return 0, fmt.Errorf("stream to gs://%s/%s: %w", bucket, object, err)
	}
	if err := wc.Close(); err != nil {
		return 0, fmt.Errorf("finalise gs://%s/%s: %w", bucket, object, err)
	}
	return n, nil
}
