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

// Package jobs wraps the Cloud Run Jobs execution API.
//
// Each call to Execute() creates a new job Execution with per-invocation
// environment variable overrides that tell the decrypt job which GCS object
// to process.
package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	run "cloud.google.com/go/run/apiv2"
	"cloud.google.com/go/run/apiv2/runpb"
	"github.com/veloxamen/decrypt-trigger/internal/config"
	"google.golang.org/api/option"
)

// Client wraps the Cloud Run Jobs execution client.
type Client struct {
	inner  *run.JobsClient
	cfg    *config.Config
	jobFQN string
}

// NewClient creates a Cloud Run Jobs client.
func NewClient(ctx context.Context, cfg *config.Config, opts ...option.ClientOption) (*Client, error) {
	c, err := run.NewJobsClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("run.NewJobsClient: %w", err)
	}

	fqn := fmt.Sprintf(
		"projects/%s/locations/%s/jobs/%s",
		cfg.GCPProject, cfg.GCPRegion, cfg.DecryptJobName,
	)

	return &Client{inner: c, cfg: cfg, jobFQN: fqn}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	return c.inner.Close()
}

// Execute submits a new Cloud Run Job Execution for the given GCS object.
// Environment variables are overridden per-execution so one job definition
// handles all files.
//
// Returns the execution resource name on success.
func (c *Client) Execute(ctx context.Context, caseID, deviceName, srcBucket, srcObject string) (string, error) {
	slog.Info("submitting job execution",
		"job", c.jobFQN,
		"case_id", caseID,
		"device_name", deviceName,
		"src_bucket", srcBucket,
		"src_object", srcObject,
	)

	// Nest the decrypt-job output under deviceName so that outputs
	// from multiple devicees do not mix.
	dstPrefix := deviceName
	if c.cfg.DstPrefix != "" {
		dstPrefix = strings.TrimSuffix(c.cfg.DstPrefix, "/") + "/" + deviceName
	}

	overrides := &runpb.RunJobRequest_Overrides{
		ContainerOverrides: []*runpb.RunJobRequest_Overrides_ContainerOverride{
			{
				Env: envVars(map[string]string{
					"SRC_BUCKET":   srcBucket,
					"SRC_OBJECT":   srcObject,
					"CASE_ID":      caseID,
					"DST_BUCKET":   c.cfg.DstBucket,
					"DST_PREFIX":   dstPrefix,
					"KMS_KEY_NAME": c.cfg.KMSKeyName,
				}),
			},
		},
	}

	op, err := c.inner.RunJob(ctx, &runpb.RunJobRequest{
		Name:      c.jobFQN,
		Overrides: overrides,
	})
	if err != nil {
		return "", fmt.Errorf("RunJob(%s): %w", c.jobFQN, err)
	}

	meta, err := op.Metadata()
	if err != nil {
		slog.Warn("could not retrieve execution metadata", "error", err)
		return "(unknown)", nil
	}

	execName := meta.GetName()
	slog.Info("execution submitted", "execution", execName)
	return execName, nil
}

// envVars converts a string map into the protobuf EnvVar slice.
func envVars(m map[string]string) []*runpb.EnvVar {
	out := make([]*runpb.EnvVar, 0, len(m))
	for k, v := range m {
		out = append(out, &runpb.EnvVar{
			Name:   k,
			Values: &runpb.EnvVar_Value{Value: v},
		})
	}
	return out
}
