// Package engine implements the core scanning orchestration.
//
// The engine is responsible for:
//   1. Taking a ScanConfig and a list of Check implementations
//   2. Distributing work across a goroutine pool
//   3. Collecting results safely (using channels, not shared state)
//   4. Handling timeouts and cancellations gracefully
//   5. Providing progress feedback
//
// Design principle: The engine knows NOTHING about what the checks do.
// It just runs them, collects results, and handles errors.
// This is the Open/Closed Principle in practice: open for extension
// (new checks), closed for modification (engine never changes when checks do).
package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/yourusername/apiscan/internal/checks"
	"github.com/yourusername/apiscan/internal/httpclient"
	"github.com/yourusername/apiscan/internal/models"
	"go.uber.org/zap"
)

// Engine orchestrates the scanning process.
type Engine struct {
	config   *models.ScanConfig
	checks   []checks.Check
	client   *httpclient.Client
	logger   *zap.Logger
}

// New creates a new Engine instance.
// The checks slice is injected — this is Dependency Injection.
// The engine doesn't import any check packages directly.
func New(
	config *models.ScanConfig,
	checkList []checks.Check,
	client *httpclient.Client,
	logger *zap.Logger,
) *Engine {
	return &Engine{
		config: config,
		checks: checkList,
		client: client,
		logger: logger,
	}
}

// job represents a unit of work: one check on one endpoint.
type job struct {
	endpoint *models.Endpoint
	check    checks.Check
}

// jobResult holds the output of a single job.
type jobResult struct {
	job      job
	findings []*models.Finding
	err      error
	duration time.Duration
}

// Scan executes all registered checks against all provided endpoints.
// It returns a ScanResult containing all findings.
//
// Concurrency model:
//   - A fixed pool of worker goroutines processes jobs from a channel
//   - Results flow back through a results channel
//   - A collector goroutine aggregates results into the final ScanResult
//   - Context cancellation propagates to all workers
func (e *Engine) Scan(ctx context.Context, endpoints []*models.Endpoint) (*models.ScanResult, error) {
	if !e.config.AuthorizationConfirmed {
		return nil, fmt.Errorf(
			"SAFETY CHECK FAILED: scanning requires explicit authorization confirmation.\n" +
				"Add --i-have-authorization flag to confirm you have permission to test this target.\n" +
				"Unauthorized security testing may be illegal in your jurisdiction.",
		)
	}

	scanID := uuid.New().String()
	startTime := time.Now()

	e.logger.Info("scan starting",
		zap.String("scan_id", scanID),
		zap.Int("endpoints", len(endpoints)),
		zap.Int("checks", len(e.checks)),
		zap.Int("concurrency", e.config.Concurrency),
	)

	result := &models.ScanResult{
		ID:        scanID,
		StartedAt: startTime,
		Status:    models.ScanStatusRunning,
		Config:    e.config,
		Endpoints: endpoints,
		Findings:  make([]*models.Finding, 0),
	}

	// Build the job queue: all combinations of (endpoint × check)
	totalJobs := len(endpoints) * len(e.checks)
	jobs := make(chan job, totalJobs)
	results := make(chan jobResult, totalJobs)

	for _, endpoint := range endpoints {
		for _, check := range e.checks {
			jobs <- job{endpoint: endpoint, check: check}
		}
	}
	close(jobs)

	// Start worker pool
	var wg sync.WaitGroup
	concurrency := e.config.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			e.worker(ctx, workerID, jobs, results)
		}(i)
	}

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	completedJobs := 0
	for jobResult := range results {
		completedJobs++
		if jobResult.err != nil {
			e.logger.Warn("check error",
				zap.String("check", jobResult.job.check.Name()),
				zap.String("endpoint", jobResult.job.endpoint.String()),
				zap.Error(jobResult.err),
			)
			continue
		}

		result.Findings = append(result.Findings, jobResult.findings...)

		if completedJobs%10 == 0 || completedJobs == totalJobs {
			e.logger.Info("scan progress",
				zap.Int("completed", completedJobs),
				zap.Int("total", totalJobs),
				zap.Int("findings_so_far", len(result.Findings)),
			)
		}
	}

	// Finalize result
	completedAt := time.Now()
	result.CompletedAt = &completedAt
	result.Duration = completedAt.Sub(startTime).String()
	result.Status = models.ScanStatusCompleted
	result.Summary.TotalChecks = totalJobs
	result.BuildSummary()

	if ctx.Err() != nil {
		result.Status = models.ScanStatusAborted
	}

	e.logger.Info("scan completed",
		zap.String("scan_id", scanID),
		zap.String("duration", result.Duration),
		zap.Int("total_findings", result.Summary.TotalFindings),
		zap.Int("critical", result.Summary.Critical),
		zap.Int("high", result.Summary.High),
		zap.Int("medium", result.Summary.Medium),
	)

	return result, nil
}

// worker processes jobs from the jobs channel and sends results to the results channel.
// Each worker runs in its own goroutine.
// Workers recover from panics to prevent a single bad check from crashing the scan.
func (e *Engine) worker(ctx context.Context, id int, jobs <-chan job, results chan<- jobResult) {
	for j := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		start := time.Now()
		findings, err := e.runCheckSafely(ctx, j)
		duration := time.Since(start)

		results <- jobResult{
			job:      j,
			findings: findings,
			err:      err,
			duration: duration,
		}
	}
}

// runCheckSafely wraps check execution in a recover() to prevent panics
// from crashing the entire scan. A buggy check should not stop other checks.
func (e *Engine) runCheckSafely(ctx context.Context, j job) (findings []*models.Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("check panicked — recovered",
				zap.String("check", j.check.Name()),
				zap.String("endpoint", j.endpoint.String()),
				zap.Any("panic", r),
			)
			err = fmt.Errorf("check %s panicked: %v", j.check.Name(), r)
		}
	}()

	return j.check.Run(ctx, j.endpoint, e.client)
}
