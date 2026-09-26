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

// Package decrypt implements the core decryption logic for the Cloud Run Job.
//
// File format produced by the collector (encrypt.go):
//
//	[Magic(8B)] [encKeyLen(4B)] [encKey(N B)]
//	  repeated until zero-length chunk:
//	    [chunkLen(4B)] [Nonce(12B)+Ciphertext]
//	[0x00000000] — termination marker
//
// The DEK (AES-256 key) is wrapped with RSA-OAEP (SHA-256) using the public
// key whose corresponding private key lives in Cloud KMS.
package decrypt

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/veloxamen/decrypt-job/internal/config"
	"github.com/veloxamen/decrypt-job/internal/gcs"
	"google.golang.org/api/option"
)

const (
	magic       = "VXMN0001"
	magicLen    = 8
	aesKeyLen   = 32
	gcmNonceLen = 12
	maxChunkLen = 64*1024*1024 + 64
)

// Decryptor wraps the Cloud KMS client.
type Decryptor struct {
	kmsClient  *kms.KeyManagementClient
	kmsKeyName string
}

// NewDecryptor creates a Decryptor backed by Cloud KMS.
func NewDecryptor(ctx context.Context, kmsKeyName string, opts ...option.ClientOption) (*Decryptor, error) {
	c, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}
	return &Decryptor{kmsClient: c, kmsKeyName: kmsKeyName}, nil
}

// Close releases the KMS client connection.
func (d *Decryptor) Close() error {
	return d.kmsClient.Close()
}

// decryptDEK calls KMS AsymmetricDecrypt to unwrap the RSA-OAEP encrypted DEK.
func (d *Decryptor) decryptDEK(ctx context.Context, encDEK []byte) ([]byte, error) {
	resp, err := d.kmsClient.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       d.kmsKeyName,
		Ciphertext: encDEK,
	})
	if err != nil {
		return nil, fmt.Errorf("kms AsymmetricDecrypt: %w", err)
	}
	if len(resp.Plaintext) != aesKeyLen {
		return nil, fmt.Errorf("unexpected DEK length from KMS: got %d, want %d", len(resp.Plaintext), aesKeyLen)
	}
	return resp.Plaintext, nil
}

// Stats holds metrics collected during a job run.
type Stats struct {
	EntriesWritten int
	BytesDecrypted int64
	Elapsed        time.Duration
}

// Job orchestrates reading from GCS, decrypting, and writing results.
type Job struct {
	GCS       *gcs.Client
	Decryptor *Decryptor
	Cfg       *config.Config
}

// Run executes the full decrypt pipeline and returns statistics.
func (j *Job) Run(ctx context.Context) (*Stats, error) {
	start := time.Now()

	rc, err := j.GCS.NewReader(ctx, j.Cfg.SrcBucket, j.Cfg.SrcObject)
	if err != nil {
		return nil, fmt.Errorf("open src object: %w", err)
	}
	defer rc.Close()

	magicBuf := make([]byte, magicLen)
	if _, err := io.ReadFull(rc, magicBuf); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if string(magicBuf) != magic {
		return nil, fmt.Errorf("invalid file magic: %q", string(magicBuf))
	}

	var encKeyLenBuf [4]byte
	if _, err := io.ReadFull(rc, encKeyLenBuf[:]); err != nil {
		return nil, fmt.Errorf("read encKeyLen: %w", err)
	}
	encKeyLen := binary.BigEndian.Uint32(encKeyLenBuf[:])
	if encKeyLen == 0 || encKeyLen > 1024 {
		return nil, fmt.Errorf("suspicious encKeyLen: %d", encKeyLen)
	}

	encDEK := make([]byte, encKeyLen)
	if _, err := io.ReadFull(rc, encDEK); err != nil {
		return nil, fmt.Errorf("read encDEK: %w", err)
	}

	slog.Info("calling KMS to decrypt DEK", "key", j.Decryptor.kmsKeyName)
	dek, err := j.Decryptor.decryptDEK(ctx, encDEK)
	if err != nil {
		return nil, fmt.Errorf("DEK decryption: %w", err)
	}
	defer clearBytes(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}

	stats := &Stats{}
	pr, pw := io.Pipe()

	decryptErr := make(chan error, 1)
	go func() {
		defer pw.Close()
		decryptErr <- decryptChunks(rc, gcm, pw)
	}()

	writeErr := j.writeEntries(ctx, pr, stats)

	if de := <-decryptErr; de != nil && writeErr == nil {
		writeErr = fmt.Errorf("chunk decryption: %w", de)
	}

	stats.Elapsed = time.Since(start)
	if writeErr != nil {
		return nil, writeErr
	}

	markerObject := buildDstObject(j.Cfg.DstPrefix, completionMarkerName)
	markerBody := fmt.Sprintf(
		`{"case_id":%q,"src_object":%q,"entries_written":%d,"bytes_decrypted":%d,"completed_at":%q}`,
		j.Cfg.CaseID, j.Cfg.SrcObject, stats.EntriesWritten, stats.BytesDecrypted,
		time.Now().UTC().Format(time.RFC3339),
	)
	if _, err := j.GCS.Upload(ctx, j.Cfg.DstBucket, markerObject, strings.NewReader(markerBody)); err != nil {
		return nil, fmt.Errorf("writing completion marker: %w", err)
	}
	slog.Info("wrote completion marker", "marker", markerObject)

	return stats, nil
}

const completionMarkerName = "_READY"

// decryptChunks reads [chunkLen(4B)][Nonce+Ciphertext] records from r,
// decrypts each with gcm, and writes the plaintext to w.
func decryptChunks(r io.Reader, gcm cipher.AEAD, w io.Writer) error {
	var lenBuf [4]byte
	for {
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("unexpected EOF before termination marker")
			}
			return fmt.Errorf("read chunk length: %w", err)
		}
		chunkLen := binary.BigEndian.Uint32(lenBuf[:])

		if chunkLen == 0 {
			return nil
		}
		if chunkLen > maxChunkLen {
			return fmt.Errorf("chunk length %d exceeds safety limit", chunkLen)
		}

		ct := make([]byte, chunkLen)
		if _, err := io.ReadFull(r, ct); err != nil {
			return fmt.Errorf("read chunk body: %w", err)
		}

		if len(ct) < gcmNonceLen {
			return fmt.Errorf("chunk too short to contain nonce: %d bytes", len(ct))
		}
		nonce := ct[:gcmNonceLen]
		ciphertext := ct[gcmNonceLen:]

		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("gcm.Open: %w (possible key mismatch or corruption)", err)
		}

		if _, err := w.Write(plaintext); err != nil {
			return fmt.Errorf("write plaintext chunk: %w", err)
		}
	}
}

// writeEntries reads the named-entry stream from r and uploads each entry to GCS.
func (j *Job) writeEntries(ctx context.Context, r io.Reader, stats *Stats) error {
	var hdr [12]byte
	for {
		_, err := io.ReadFull(r, hdr[:])
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read entry header: %w", err)
		}

		nameLen := binary.BigEndian.Uint32(hdr[0:4])
		dataLen := binary.BigEndian.Uint64(hdr[4:12])

		if nameLen == 0 || nameLen > 4096 {
			return fmt.Errorf("suspicious entry nameLen: %d", nameLen)
		}
		if dataLen > 10*1024*1024*1024 {
			return fmt.Errorf("suspicious entry dataLen: %d", dataLen)
		}

		nameBuf := make([]byte, nameLen)
		if _, err := io.ReadFull(r, nameBuf); err != nil {
			return fmt.Errorf("read entry name: %w", err)
		}
		entryName := string(nameBuf)

		dstObject := buildDstObject(j.Cfg.DstPrefix, entryName)
		lr := io.LimitReader(r, int64(dataLen))

		n, err := j.GCS.Upload(ctx, j.Cfg.DstBucket, dstObject, lr)
		if err != nil {
			return fmt.Errorf("upload entry %q: %w", entryName, err)
		}

		stats.EntriesWritten++
		stats.BytesDecrypted += n
		slog.Info("entry written", "name", entryName, "bytes", n, "dst", dstObject)
	}
}

// buildDstObject constructs the destination GCS object path.
func buildDstObject(prefix, entryName string) string {
	if prefix == "" {
		return entryName
	}
	return strings.TrimSuffix(prefix, "/") + "/" + entryName
}

// clearBytes zeroes key material to reduce its lifetime in memory.
func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
