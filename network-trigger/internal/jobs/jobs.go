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
package jobs

import (
	"context"
	"fmt"
	"log/slog"

	run "cloud.google.com/go/run/apiv2"
	"cloud.google.com/go/run/apiv2/runpb"
	"github.com/veloxamen/network-trigger/internal/config"
	"google.golang.org/api/option"
)

// Client wraps the Cloud Run Jobs execution client.
type Client struct {
	inner  *run.JobsClient
	cfg    *config.Config
	jobFQN string
}

// NewClient constructs a jobs.Client.
func NewClient(ctx context.Context, cfg *config.Config, opts ...option.ClientOption) (*Client, error) {
	c, err := run.NewJobsClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("run.NewJobsClient: %w", err)
	}
	jobFQN := fmt.Sprintf("projects/%s/locations/%s/jobs/%s", cfg.GCPProject, cfg.Region, cfg.NetworkJobName)
	return &Client{inner: c, cfg: cfg, jobFQN: jobFQN}, nil
}

// Close releases the underlying client.
func (c *Client) Close() error {
	return c.inner.Close()
}

// Execute kicks off a network-job execution for the given object.
func (c *Client) Execute(ctx context.Context, srcObject, logType string) (string, error) {
	slog.Info("submitting network-job execution", "job", c.jobFQN, "src_object", srcObject, "log_type", logType)

	overrides := &runpb.RunJobRequest_Overrides{
		ContainerOverrides: []*runpb.RunJobRequest_Overrides_ContainerOverride{
			{
				Env: []*runpb.EnvVar{
					{Name: "SRC_OBJECT", Values: &runpb.EnvVar_Value{Value: srcObject}},
					{Name: "LOG_TYPE", Values: &runpb.EnvVar_Value{Value: logType}},
				},
			},
		},
	}

	op, err := c.inner.RunJob(ctx, &runpb.RunJobRequest{
		Name:      c.jobFQN,
		Overrides: overrides,
	})
	if err != nil {
		return "", fmt.Errorf("RunJob: %w", err)
	}

	meta, err := op.Metadata()
	if err != nil {
		slog.Warn("submitted network-job but could not read execution metadata", "error", err)
		return "", nil
	}
	return meta.GetName(), nil
}
