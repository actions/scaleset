// Package metrics exposes the ARC listener series (gha_*), with the same
// names and labels so existing dashboards keep working, and the dispatcher
// series (ci_dispatcher_*).
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/actions/scaleset"
)

var (
	queueLabels  = []string{"name", "namespace", "repository"}
	jobLabels    = []string{"repository", "job_name", "event_name"}
	resultLabels = []string{"repository", "job_name", "event_name", "job_result"}
	startBuckets = []float64{1, 3, 5, 10, 20, 30, 60, 90, 120, 180, 300, 600, 1200, 1800, 3600}
	execBuckets  = []float64{10, 30, 60, 120, 300, 600, 900, 1200, 1800, 2700, 3600, 7200, 10800, 21600}
	claimBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120, 300}
)

// Metrics holds every collector.
type Metrics struct {
	registry *prometheus.Registry

	StartedJobs    *prometheus.CounterVec
	CompletedJobs  *prometheus.CounterVec
	AssignedJobs   *prometheus.GaugeVec
	RunningJobs    *prometheus.GaugeVec
	Registered     *prometheus.GaugeVec
	Busy           *prometheus.GaugeVec
	Idle           *prometheus.GaugeVec
	MinRunners     *prometheus.GaugeVec
	MaxRunners     *prometheus.GaugeVec
	DesiredRunners *prometheus.GaugeVec
	StartupSeconds *prometheus.HistogramVec
	ExecSeconds    *prometheus.HistogramVec

	Sessions      *prometheus.GaugeVec
	SessionErrors *prometheus.CounterVec
	WarmPods      *prometheus.GaugeVec
	ClaimSeconds  *prometheus.HistogramVec
	BudgetBlocked *prometheus.GaugeVec
	BudgetFree    *prometheus.GaugeVec
	PodsCreated   *prometheus.CounterVec
	PodErrors     *prometheus.CounterVec
	RateRemaining prometheus.Gauge
	GCRemoved     *prometheus.CounterVec
}

// New registers every collector on a fresh registry.
func New() *Metrics {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	g := func(name, help string, labels ...string) *prometheus.GaugeVec {
		v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
		r.MustRegister(v)
		return v
	}
	c := func(name, help string, labels ...string) *prometheus.CounterVec {
		v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
		r.MustRegister(v)
		return v
	}
	h := func(name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
		v := prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Help: help, Buckets: buckets}, labels)
		r.MustRegister(v)
		return v
	}
	m := &Metrics{registry: r}
	m.StartedJobs = c("gha_started_jobs_total", "Total number of jobs started.", jobLabels...)
	m.CompletedJobs = c("gha_completed_jobs_total", "Total number of jobs completed.", resultLabels...)
	m.AssignedJobs = g("gha_assigned_jobs", "Number of jobs assigned to this scale set.", queueLabels...)
	m.RunningJobs = g("gha_running_jobs", "Number of jobs running (or about to be run).", queueLabels...)
	m.Registered = g("gha_registered_runners", "Number of runners registered by the scale set.", queueLabels...)
	m.Busy = g("gha_busy_runners", "Number of registered runners running a job.", queueLabels...)
	m.Idle = g("gha_idle_runners", "Number of registered runners not running a job.", queueLabels...)
	m.MinRunners = g("gha_min_runners", "Minimum number of runners.", queueLabels...)
	m.MaxRunners = g("gha_max_runners", "Maximum number of runners.", queueLabels...)
	m.DesiredRunners = g("gha_desired_runners", "Number of runners desired by the scale set.", queueLabels...)
	m.StartupSeconds = h("gha_job_startup_duration_seconds", "Time from the scale set assignment to the runner assignment.", startBuckets, jobLabels...)
	m.ExecSeconds = h("gha_job_execution_duration_seconds", "Time from the runner assignment to the job end.", execBuckets, resultLabels...)

	m.Sessions = g("ci_dispatcher_sessions", "Message sessions by state.", "state")
	m.SessionErrors = c("ci_dispatcher_session_errors_total", "Session failures by reason.", "reason")
	m.WarmPods = g("ci_dispatcher_warm_pods", "Warm pods by profile and state.", "profile", "state")
	m.ClaimSeconds = h("ci_dispatcher_claim_duration_seconds", "Time an agent waited for its configuration.", claimBuckets, "profile", "source")
	m.BudgetBlocked = g("ci_dispatcher_budget_blocked", "Runners refused (or that would be with enforce off) by the node budget.", "profile")
	m.BudgetFree = g("ci_dispatcher_budget_free", "Free runner places per capped node.", "node")
	m.PodsCreated = c("ci_dispatcher_pods_created_total", "Runner pods created.", "profile", "source")
	m.PodErrors = c("ci_dispatcher_pod_errors_total", "Pod operations that failed.", "operation")
	m.RateRemaining = prometheus.NewGauge(prometheus.GaugeOpts{Name: "ci_dispatcher_github_ratelimit_remaining", Help: "Last X-RateLimit-Remaining seen on the REST API."})
	r.MustRegister(m.RateRemaining)
	m.GCRemoved = c("ci_dispatcher_gc_removed_total", "Objects removed by the garbage collector.", "kind")
	return m
}

// Handler serves /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Queue identifies the gauge labels of a scale set.
type Queue struct {
	Name, Namespace, Repository string
}

func (q Queue) labels() prometheus.Labels {
	return prometheus.Labels{"name": q.Name, "namespace": q.Namespace, "repository": q.Repository}
}

// SetStatistics publishes the statistics of a scale set message.
func (m *Metrics) SetStatistics(q Queue, st *scaleset.RunnerScaleSetStatistic, desired, minRunners, maxRunners int) {
	l := q.labels()
	if st != nil {
		m.AssignedJobs.With(l).Set(float64(st.TotalAssignedJobs))
		m.RunningJobs.With(l).Set(float64(st.TotalRunningJobs))
		m.Registered.With(l).Set(float64(st.TotalRegisteredRunners))
		m.Busy.With(l).Set(float64(st.TotalBusyRunners))
		m.Idle.With(l).Set(float64(st.TotalIdleRunners))
	}
	m.DesiredRunners.With(l).Set(float64(desired))
	m.MinRunners.With(l).Set(float64(minRunners))
	m.MaxRunners.With(l).Set(float64(maxRunners))
}

// JobStarted records a job start, like the ARC listener: startup is the time
// between the scale set assignment and the runner assignment.
func (m *Metrics) JobStarted(repo string, j *scaleset.JobStarted) {
	m.StartedJobs.WithLabelValues(repo, j.JobDisplayName, j.EventName).Inc()
	if !j.RunnerAssignTime.IsZero() && !j.ScaleSetAssignTime.IsZero() {
		d := j.RunnerAssignTime.Sub(j.ScaleSetAssignTime)
		if d >= 0 {
			m.StartupSeconds.WithLabelValues(repo, j.JobDisplayName, j.EventName).Observe(d.Seconds())
		}
	}
}

// JobCompleted records a job end.
func (m *Metrics) JobCompleted(repo string, j *scaleset.JobCompleted) {
	m.CompletedJobs.WithLabelValues(repo, j.JobDisplayName, j.EventName, j.Result).Inc()
	if !j.FinishTime.IsZero() && !j.RunnerAssignTime.IsZero() {
		d := j.FinishTime.Sub(j.RunnerAssignTime)
		if d >= 0 {
			m.ExecSeconds.WithLabelValues(repo, j.JobDisplayName, j.EventName, j.Result).Observe(d.Seconds())
		}
	}
}

// ObserveClaim records how long an agent waited for its configuration.
func (m *Metrics) ObserveClaim(profile, source string, d time.Duration) {
	m.ClaimSeconds.WithLabelValues(profile, source).Observe(d.Seconds())
}
