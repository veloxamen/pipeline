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

// Package gcs wraps the Google Cloud Storage client for the Plaso job.
package gcs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
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

// DownloadPrefix lists objects under gs://bucket/prefix and downloads
// them into destDir, preserving relative path structures.
func (c *Client) DownloadPrefix(ctx context.Context, bucket, prefix, destDir string) (int, error) {
	if prefix != "" {
		prefix = strings.TrimSuffix(prefix, "/") + "/"
	}
	it := c.inner.Bucket(bucket).Objects(ctx, &storage.Query{Prefix: prefix})

	count := 0
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return count, fmt.Errorf("listing gs://%s/%s: %w", bucket, prefix, err)
		}

		if strings.HasSuffix(attrs.Name, "/") {
			continue
		}

		rel := strings.TrimPrefix(attrs.Name, prefix)
		localPath := filepath.Join(destDir, filepath.FromSlash(rel))

		if err := c.downloadOne(ctx, bucket, attrs.Name, localPath); err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}

func (c *Client) downloadOne(ctx context.Context, bucket, object, localPath string) error {
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", localPath, err)
	}

	rc, err := c.inner.Bucket(bucket).Object(object).NewReader(ctx)
	if err != nil {
		return fmt.Errorf("open reader for gs://%s/%s: %w", bucket, object, err)
	}
	defer rc.Close()

	f, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", localPath, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, rc); err != nil {
		return fmt.Errorf("download gs://%s/%s: %w", bucket, object, err)
	}
	return nil
}

// UploadFile uploads a single local file to gs://bucket/object.
func (c *Client) UploadFile(ctx context.Context, bucket, object, localPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", localPath, err)
	}
	defer f.Close()

	wc := c.inner.Bucket(bucket).Object(object).NewWriter(ctx)
	wc.ContentType = "application/x-ndjson"

	if _, err := io.Copy(wc, f); err != nil {
		wc.Close()
		return fmt.Errorf("upload gs://%s/%s: %w", bucket, object, err)
	}
	return wc.Close()
}
