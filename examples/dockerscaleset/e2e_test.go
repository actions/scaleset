package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-github/v79/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
	if os.Getenv("E2E") != "true" {
		t.Skip("Skipping E2E test; set E2E=true to run")
	}

	configURL := mustGetEnv(t, "E2E_SCALESET_URL")
	name := mustGetEnv(t, "E2E_SCALESET_NAME")

	workflowEnv := mustE2EWorkflowEnv(t, name)
	runArgs := mustE2ECommandArgs(t, configURL, name)

	tempDir, err := os.MkdirTemp("", "e2e-dockerscaleset-")
	require.NoError(t, err, "Failed to create temp dir")
	defer os.RemoveAll(tempDir)

	binaryPath := filepath.Join(tempDir, "dockerscaleset")

	// Build the dockerscaleset binary in temp dir
	{
		cmd := exec.Command("go", "build", "-o", binaryPath, ".")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to build dockerscaleset: %s", output)
	}

	// Fatal channel
	testErrCh := make(chan error, 2)

	runCmd := exec.Command(binaryPath, runArgs...)
	stdout, err := runCmd.StdoutPipe()
	runCmd.Stderr = os.Stderr
	require.NoError(t, err, "Failed to get stdout pipe")
	err = runCmd.Start()
	require.NoError(t, err, "Failed to start dockerscaleset")

	// Command exit error
	cmdCh := make(chan error, 1)
	t.Cleanup(func() {
		_ = runCmd.Process.Signal(os.Interrupt)
		<-cmdCh
	})

	// Wait for log line
	waitCh := make(chan struct{}, 1)

	var (
		bufMu sync.Mutex
		buf   bytes.Buffer
	)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			bufMu.Lock()
			buf.WriteString(line + "\n")
			bufMu.Unlock()
			if strings.Contains(line, "Getting next message") {
				close(waitCh)
				break
			}
		}
		if err := scanner.Err(); err != nil {
			testErrCh <- fmt.Errorf("error reading dockerscaleset stdout: %w", err)
			return
		}

		cmdCh <- runCmd.Wait()
		close(cmdCh)
	}()

	runID, err := workflowEnv.triggerWorkflowDispatch(t, t.Context())
	require.NoError(t, err, "Failed to trigger workflow")

	statusCh := make(chan *WorkflowRun, 1)
	go func() {
		select {
		case <-waitCh:
		case <-time.After(30 * time.Second):
			bufMu.Lock()
			logs := buf.String()
			bufMu.Unlock()
			testErrCh <- fmt.Errorf("timeout waiting for dockerscaleset to be ready; logs:\n%s", logs)
			return
		}
		status, err := workflowEnv.waitForWorkflowCompletion(t, t.Context(), runID, 10*time.Minute)
		if err != nil {
			testErrCh <- fmt.Errorf("failed to wait for workflow completion: %w", err)
			return
		}
		statusCh <- status
	}()

	select {
	case err := <-cmdCh:
		select {
		case status := <-statusCh:
			assert.Equal(t, "completed", status.Status)
			assert.Equal(t, "success", status.Conclusion)
		case <-time.After(30 * time.Second):
			bufMu.Lock()
			logs := buf.String()
			bufMu.Unlock()
			t.Fatalf("Timeout waiting for workflow status after dockerscaleset exited\nexit: %v\nlogs:%s\n", err, logs)
		}
	case status := <-statusCh:
		assert.NotNil(t, status, "WorkflowRun status is nil")
		assert.Equal(t, "completed", status.Status)
		assert.Equal(t, "success", status.Conclusion)
		return
	case err := <-testErrCh:
		t.Fatal(err)
	}
}

type e2eWorkflowEnv struct {
	targetOrg  string
	targetRepo string
	targetFile string

	scalesetName string
	client       *github.Client
}

func mustE2EWorkflowEnv(t *testing.T, scalesetName string) *e2eWorkflowEnv {
	return &e2eWorkflowEnv{
		targetOrg:    mustGetEnv(t, "E2E_WORKFLOW_TARGET_ORG"),
		targetRepo:   mustGetEnv(t, "E2E_WORKFLOW_TARGET_REPO"),
		targetFile:   mustGetEnv(t, "E2E_WORKFLOW_TARGET_FILE"),
		scalesetName: scalesetName,
		client:       github.NewClient(nil).WithAuthToken(mustGetEnv(t, "E2E_WORKFLOW_GITHUB_TOKEN")),
	}
}

func mustE2ECommandArgs(t *testing.T, configURL, name string) []string {
	args := []string{
		"--url", configURL,
		"--name", name,
		"--log-level", "debug",
	}

	// GitHub App credentials
	var (
		clientID       string
		installationID int
		privateKeyPath string
	)

	// GitHub token
	var token string

	clientID = os.Getenv("E2E_SCALESET_GITHUB_APP_CLIENT_ID")
	installationIDStr := os.Getenv("E2E_SCALESET_GITHUB_APP_INSTALLATION_ID")
	privateKeyPath = os.Getenv("E2E_SCALESET_GITHUB_APP_PRIVATE_KEY_PATH")

	if clientID != "" && installationIDStr != "" && privateKeyPath != "" {
		id, err := strconv.Atoi(installationIDStr)
		require.NoError(t, err, "Invalid E2E_SCALESET_GITHUB_APP_INSTALLATION_ID")
		installationID = id
		args = append(args,
			"--app-client-id", clientID,
			"--app-installation-id", fmt.Sprintf("%d", installationID),
			"--app-private-key", privateKeyPath,
		)
	} else {
		token = os.Getenv("E2E_SCALESET_GITHUB_TOKEN")
		require.NotEmpty(t, token, "E2E_SCALESET_GITHUB_TOKEN must be set if GitHub App credentials are not provided")
		args = append(args,
			"--token", token,
		)
	}

	runnerGroup := os.Getenv("E2E_SCALESET_RUNNER_GROUP")
	if runnerGroup != "" {
		args = append(args,
			"--runner-group", runnerGroup,
		)
	}

	minRunners := 0
	if minRunnersStr := os.Getenv("E2E_SCALESET_MIN_RUNNERS"); minRunnersStr != "" {
		m, err := strconv.Atoi(minRunnersStr)
		require.NoError(t, err, "Invalid E2E_SCALESET_MIN_RUNNERS")
		minRunners = m
		require.GreaterOrEqual(t, minRunners, 0, "E2E_SCALESET_MIN_RUNNERS must be >= 0")
	}

	maxRunners := 10
	if maxRunnersStr := os.Getenv("E2E_SCALESET_MAX_RUNNERS"); maxRunnersStr != "" {
		m, err := strconv.Atoi(maxRunnersStr)
		require.NoError(t, err, "Invalid E2E_SCALESET_MAX_RUNNERS")
		maxRunners = m
		require.GreaterOrEqual(t, maxRunners, 0, "E2E_SCALESET_MAX_RUNNERS must be >= 0")
	}

	require.GreaterOrEqual(t, maxRunners, minRunners, "E2E_SCALESET_MAX_RUNNERS must be >= E2E_SCALESET_MIN_RUNNERS")

	args = append(args,
		"--min-runners", strconv.Itoa(minRunners),
		"--max-runners", strconv.Itoa(maxRunners),
	)

	return args
}

type WorkflowRun struct {
	ID         int    `json:"id"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	CreatedAt  string `json:"created_at"`
}

func (env *e2eWorkflowEnv) triggerWorkflowDispatch(t *testing.T, ctx context.Context) (int, error) {
	dispatchTime := time.Now().UTC()

	resp, err := env.client.Actions.CreateWorkflowDispatchEventByFileName(
		ctx,
		env.targetOrg,
		env.targetRepo,
		env.targetFile,
		github.CreateWorkflowDispatchEventRequest{
			Ref: "main",
			Inputs: map[string]any{
				"scaleset_name": env.scalesetName,
			},
		},
	)
	require.NoError(t, err, "Failed to create workflow dispatch")
	require.Equal(t, 204, resp.StatusCode, "Unexpected status code from workflow dispatch")

	// Wait a bit for the run to be created
	time.Sleep(10 * time.Second)

	// List runs with event=workflow_dispatch and since=dispatchTime
	opts := &github.ListWorkflowRunsOptions{
		Event:   "workflow_dispatch",
		Created: ">=" + dispatchTime.Format(time.RFC3339),
		ListOptions: github.ListOptions{
			PerPage: 10,
		},
	}
	runs, _, err := env.client.Actions.ListWorkflowRunsByFileName(
		t.Context(),
		env.targetOrg,
		env.targetRepo,
		env.targetFile,
		opts,
	)
	require.NoError(t, err, "Failed to list workflow runs")
	require.Greater(t, len(runs.WorkflowRuns), 0, "No workflow runs found after dispatch")

	// Sort by created_at desc, take the first (most recent)
	var latestRun *github.WorkflowRun
	var latestTime time.Time
	for _, run := range runs.WorkflowRuns {
		createdAt := run.CreatedAt.Time
		if createdAt.After(latestTime) {
			latestTime = createdAt
			latestRun = run
		}
	}

	if latestRun == nil {
		return 0, fmt.Errorf("no workflow runs found after dispatch")
	}

	return int(latestRun.GetID()), nil
}

func (env *e2eWorkflowEnv) waitForWorkflowCompletion(t *testing.T, ctx context.Context, runID int, timeout time.Duration) (*WorkflowRun, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			run, _, err := env.client.Actions.GetWorkflowRunByID(ctx, env.targetOrg, env.targetRepo, int64(runID))
			require.NoError(t, err, "Failed to get workflow run by ID")

			if run.GetStatus() == "completed" {
				return &WorkflowRun{
					ID:         int(run.GetID()),
					Status:     run.GetStatus(),
					Conclusion: run.GetConclusion(),
					CreatedAt:  run.GetCreatedAt().Format(time.RFC3339),
				}, nil
			}
		}
	}
}

func mustGetEnv(t *testing.T, key string) string {
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("Environment variable %s not set", key)
	}
	return value
}
