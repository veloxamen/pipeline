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

// Package jobs wraps the Google Batch API to submit plaso-job executions.
package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	batch "cloud.google.com/go/batch/apiv1"
	"cloud.google.com/go/batch/apiv1/batchpb"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/veloxamen/plaso-trigger/internal/config"
)

const scratchDiskDeviceName = "plaso-scratch"
const scratchMountPath = "/mnt/disks/plaso-scratch"

// Client wraps the Batch Jobs client.
type Client struct {
	inner  *batch.Client
	cfg    *config.Config
	parent string
}

// NewClient constructs a jobs.Client.
func NewClient(ctx context.Context, cfg *config.Config, opts ...option.ClientOption) (*Client, error) {
	c, err := batch.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("batch.NewClient: %w", err)
	}
	parent := fmt.Sprintf("projects/%s/locations/%s", cfg.GCPProject, cfg.Region)
	return &Client{inner: c, cfg: cfg, parent: parent}, nil
}

// Close releases the underlying client.
func (c *Client) Close() error {
	return c.inner.Close()
}

// Execute submits a new Batch Job running plaso-job for the given case ID.
func (c *Client) Execute(ctx context.Context, caseID string) (string, error) {
	jobID := fmt.Sprintf("plaso-job-%s-%d", sanitizeID(caseID), time.Now().UTC().UnixNano())
	slog.Info("submitting plaso-job Batch execution", "job_id", jobID, "case_id", caseID)

	provisioningModel := batchpb.AllocationPolicy_STANDARD
	if c.cfg.ProvisioningModel == "SPOT" {
		provisioningModel = batchpb.AllocationPolicy_SPOT
	}

	job := &batchpb.Job{
		TaskGroups: []*batchpb.TaskGroup{
			{
				TaskCount: 1,
				TaskSpec: &batchpb.TaskSpec{
					Runnables: []*batchpb.Runnable{
						{
							Executable: &batchpb.Runnable_Container_{
								Container: &batchpb.Runnable_Container{
									ImageUri: c.cfg.PlasoJobImage,
								},
							},
						},
					},
					ComputeResource: &batchpb.ComputeResource{
						CpuMilli:  c.cfg.CPUMilli,
						MemoryMib: c.cfg.MemoryMib,
					},
					MaxRunDuration: durationpb.New(c.cfg.MaxRunDuration),
					MaxRetryCount:  c.cfg.MaxRetryCount,
					Volumes: []*batchpb.Volume{
						{
							Source:       &batchpb.Volume_DeviceName{DeviceName: scratchDiskDeviceName},
							MountPath:    scratchMountPath,
							MountOptions: []string{"rw"},
						},
					},
					Environment: &batchpb.Environment{
						Variables: map[string]string{
							"SRC_BUCKET": c.cfg.SrcBucket,
							"DST_BUCKET": c.cfg.DstBucket,
							"CASE_ID":    caseID,
							"WORK_DIR":   scratchMountPath + "/plaso-job",
						},
					},
				},
			},
		},
		AllocationPolicy: &batchpb.AllocationPolicy{
			ServiceAccount: &batchpb.ServiceAccount{Email: c.cfg.PlasoJobSA},
			Instances: []*batchpb.AllocationPolicy_InstancePolicyOrTemplate{
				{
					PolicyTemplate: &batchpb.AllocationPolicy_InstancePolicyOrTemplate_Policy{
						Policy: &batchpb.AllocationPolicy_InstancePolicy{
							MachineType:       c.cfg.MachineType,
							ProvisioningModel: provisioningModel,
							BootDisk: &batchpb.AllocationPolicy_Disk{
								Type: "pd-standard",
							},
							Disks: []*batchpb.AllocationPolicy_AttachedDisk{
								{
									DeviceName: scratchDiskDeviceName,
									Attached: &batchpb.AllocationPolicy_AttachedDisk_NewDisk{
										NewDisk: &batchpb.AllocationPolicy_Disk{
											Type:   "pd-balanced",
											SizeGb: c.cfg.ScratchDiskGB,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Labels: map[string]string{
			"case-id": sanitizeID(caseID),
			"trigger": "plaso-trigger",
		},
		LogsPolicy: &batchpb.LogsPolicy{Destination: batchpb.LogsPolicy_CLOUD_LOGGING},
	}

	created, err := c.inner.CreateJob(ctx, &batchpb.CreateJobRequest{
		Parent: c.parent,
		JobId:  jobID,
		Job:    job,
	})
	if err != nil {
		return "", fmt.Errorf("CreateJob: %w", err)
	}
	return created.GetName(), nil
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := b.String()
	if len(out) > 40 {
		out = out[:40]
	}
	return strings.Trim(out, "-")
}
