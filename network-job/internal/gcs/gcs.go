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

// Package gcs wraps the Google Cloud Storage client with the single
// operation network-job needs: opening one raw log object for streaming
// read.
package gcs

import (
	"context"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
)

// Client wraps *storage.Client.
type Client struct {
	inner *storage.Client
}

// NewClient creates a GCS client using application default credentials.
func NewClient(ctx context.Context) (*Client, error) {
	c, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage.NewClient: %w", err)
	}
	return &Client{inner: c}, nil
}

// Close releases the underlying client.
func (c *Client) Close() error {
	return c.inner.Close()
}

// OpenObject returns a streaming reader for gs://bucket/object. The
// caller must Close it.
func (c *Client) OpenObject(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
	rc, err := c.inner.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("open reader for gs://%s/%s: %w", bucket, object, err)
	}
	return rc, nil
}
