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

// Package archive recursively unwraps zip, gzip, and tar.gz/tgz
// containers so that network-job can accept raw log objects OR any of
// those archive formats uploaded to the same GCS bucket. All entries
// found inside an archive are handled by the same log-type parser
// selected for the whole job (LOG_TYPE), on the assumption that one
// upload only ever bundles logs of a single vendor/format together.
package archive

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxDepth caps archive-within-archive nesting to guard against
// unreasonably (or maliciously) deep nesting, e.g. a "zip bomb" of
// nested containers. Five levels comfortably covers any legitimate
// upload shape (e.g. a .zip of .tar.gz files) while still bounding
// recursion.
const maxDepth = 5

// FileHandler processes one fully-decompressed, non-archive file. name
// is the entry's path as recorded in its container (or the original GCS
// object name at the top level); r streams its raw content.
type FileHandler func(ctx context.Context, name string, r io.Reader) error

// Walk inspects name's extension and, recursively, the extension of any
// nested entries, transparently decompressing zip/gz/tar.gz/tgz/tar
// containers before calling handle on each raw (non-archive) file it
// finds. A plain, non-archive object is passed straight to handle
// unchanged — existing single-file uploads work exactly as before.
func Walk(ctx context.Context, name string, r io.Reader, handle FileHandler) error {
	return walk(ctx, name, r, 0, handle)
}

func walk(ctx context.Context, name string, r io.Reader, depth int, handle FileHandler) error {
	if depth > maxDepth {
		return fmt.Errorf("archive nesting too deep (>%d levels) at %q — aborting", maxDepth, name)
	}

	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		return walkTarGz(ctx, name, r, depth, handle)
	case strings.HasSuffix(lower, ".tar"):
		return walkTar(ctx, tar.NewReader(r), depth, handle)
	case strings.HasSuffix(lower, ".gz"):
		return walkGzip(ctx, name, r, depth, handle)
	case strings.HasSuffix(lower, ".zip"):
		return walkZip(ctx, name, r, depth, handle)
	default:
		return handle(ctx, name, r)
	}
}

// walkGzip decompresses a single-file gzip stream (i.e. not a .tar.gz —
// that case is handled by walkTarGz before this is reached) and
// recurses on the decompressed content, in case the inner file is
// itself an archive (e.g. "events.zip.gz", however unlikely) or, the
// common case, a plain log file (e.g. "events.log.gz").
func walkGzip(ctx context.Context, name string, r io.Reader, depth int, handle FileHandler) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("open gzip %q: %w", name, err)
	}
	defer gzr.Close()

	innerName := strings.TrimSuffix(name, filepath.Ext(name))
	return walk(ctx, innerName, gzr, depth+1, handle)
}

// walkTarGz decompresses a .tar.gz/.tgz stream and recurses into each
// regular-file entry.
func walkTarGz(ctx context.Context, name string, r io.Reader, depth int, handle FileHandler) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("open gzip layer of %q: %w", name, err)
	}
	defer gzr.Close()

	return walkTar(ctx, tar.NewReader(gzr), depth, handle)
}

// walkTar iterates a tar stream's entries and recurses into each
// regular file (skipping directories and other special entry types).
func walkTar(ctx context.Context, tr *tar.Reader, depth int, handle FileHandler) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if err := walk(ctx, hdr.Name, tr, depth+1, handle); err != nil {
			return fmt.Errorf("entry %q: %w", hdr.Name, err)
		}
	}
}

// walkZip needs random access (io.ReaderAt + size), which a streaming
// GCS object reader doesn't provide, so it first buffers the full
// stream to a temp file on local disk, then reopens that file for zip
// reading. The temp file is removed before returning.
func walkZip(ctx context.Context, name string, r io.Reader, depth int, handle FileHandler) error {
	tmp, err := os.CreateTemp("", "network-job-zip-*")
	if err != nil {
		return fmt.Errorf("create temp file for zip %q: %w", name, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	defer tmp.Close()

	size, err := io.Copy(tmp, r)
	if err != nil {
		return fmt.Errorf("buffer zip %q to disk: %w", name, err)
	}

	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		return fmt.Errorf("open zip %q: %w", name, err)
	}

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if err := func() error {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("open zip entry %q: %w", f.Name, err)
			}
			defer rc.Close()
			return walk(ctx, f.Name, rc, depth+1, handle)
		}(); err != nil {
			return fmt.Errorf("entry %q: %w", f.Name, err)
		}
	}
	return nil
}
