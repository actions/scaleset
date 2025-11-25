package scaleset

import (
	"time"

	"github.com/google/uuid"
)

const DefaultRunnerGroup = "default"

type MessageType string

// message types
const (
	MessageTypeJobAssigned  MessageType = "JobAssigned"
	MessageTypeJobStarted   MessageType = "JobStarted"
	MessageTypeJobCompleted MessageType = "JobCompleted"
)

type Int64List struct {
	Count int     `json:"count"`
	Value []int64 `json:"value"`
}

type JobAvailable struct {
	AcquireJobURL string `json:"acquireJobUrl"`
	JobMessageBase
}

type JobAssigned struct {
	JobMessageBase
}

type JobStarted struct {
	RunnerID   int    `json:"runnerId"`
	RunnerName string `json:"runnerName"`
	JobMessageBase
}

type JobCompleted struct {
	Result     string `json:"result"`
	RunnerID   int    `json:"runnerId"`
	RunnerName string `json:"runnerName"`
	JobMessageBase
}

type JobMessageType struct {
	MessageType MessageType `json:"messageType"`
}

type JobMessageBase struct {
	JobMessageType
	RunnerRequestID    int64     `json:"runnerRequestId"`
	RepositoryName     string    `json:"repositoryName"`
	OwnerName          string    `json:"ownerName"`
	JobID              string    `json:"jobId"`
	JobWorkflowRef     string    `json:"jobWorkflowRef"`
	JobDisplayName     string    `json:"jobDisplayName"`
	WorkflowRunID      int64     `json:"workflowRunId"`
	EventName          string    `json:"eventName"`
	RequestLabels      []string  `json:"requestLabels"`
	QueueTime          time.Time `json:"queueTime"`
	ScaleSetAssignTime time.Time `json:"scaleSetAssignTime"`
	RunnerAssignTime   time.Time `json:"runnerAssignTime"`
	FinishTime         time.Time `json:"finishTime"`
}

type Label struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type RunnerGroup struct {
	ID        uint64 `json:"id"`
	Name      string `json:"name"`
	Size      uint64 `json:"size"`
	IsDefault bool   `json:"isDefaultGroup"`
}

type RunnerGroupList struct {
	Count        int           `json:"count"`
	RunnerGroups []RunnerGroup `json:"value"`
}

type RunnerScaleSet struct {
	ID                 uint64                   `json:"id,omitempty"`
	Name               string                   `json:"name,omitempty"`
	RunnerGroupID      uint64                   `json:"runnerGroupId,omitempty"`
	RunnerGroupName    string                   `json:"runnerGroupName,omitempty"`
	Labels             []Label                  `json:"labels,omitempty"`
	RunnerSetting      RunnerSetting            `json:"RunnerSetting,omitempty"`
	CreatedOn          time.Time                `json:"createdOn,omitempty"`
	RunnerJitConfigURL string                   `json:"runnerJitConfigUrl,omitempty"`
	Statistics         *RunnerScaleSetStatistic `json:"statistics,omitempty"`
}

type RunnerScaleSetJitRunnerSetting struct {
	Name       string `json:"name"`
	WorkFolder string `json:"workFolder"`
}

type RunnerScaleSetMessage struct {
	MessageID   uint64                   `json:"messageId"`
	MessageType string                   `json:"messageType"`
	Body        string                   `json:"body"`
	Statistics  *RunnerScaleSetStatistic `json:"statistics"`
}

type runnerScaleSetsResponse struct {
	Count           uint64           `json:"count"`
	RunnerScaleSets []RunnerScaleSet `json:"value"`
}

type RunnerScaleSetSession struct {
	SessionID               uuid.UUID                `json:"sessionId,omitempty"`
	OwnerName               string                   `json:"ownerName,omitempty"`
	RunnerScaleSet          *RunnerScaleSet          `json:"runnerScaleSet,omitempty"`
	MessageQueueURL         string                   `json:"messageQueueUrl,omitempty"`
	MessageQueueAccessToken string                   `json:"messageQueueAccessToken,omitempty"`
	Statistics              *RunnerScaleSetStatistic `json:"statistics,omitempty"`
}

type RunnerScaleSetStatistic struct {
	TotalAvailableJobs     uint64 `json:"totalAvailableJobs"`
	TotalAcquiredJobs      uint64 `json:"totalAcquiredJobs"`
	TotalAssignedJobs      uint64 `json:"totalAssignedJobs"`
	TotalRunningJobs       uint64 `json:"totalRunningJobs"`
	TotalRegisteredRunners uint64 `json:"totalRegisteredRunners"`
	TotalBusyRunners       uint64 `json:"totalBusyRunners"`
	TotalIdleRunners       uint64 `json:"totalIdleRunners"`
}

type RunnerSetting struct {
	Ephemeral     bool `json:"ephemeral,omitempty"`
	IsElastic     bool `json:"isElastic,omitempty"`
	DisableUpdate bool `json:"disableUpdate,omitempty"`
}

type RunnerReferenceList struct {
	Count            int               `json:"count"`
	RunnerReferences []RunnerReference `json:"value"`
}

type RunnerReference struct {
	ID               int    `json:"id"`
	Name             string `json:"name"`
	RunnerScaleSetID int    `json:"runnerScaleSetId"`
}

type RunnerScaleSetJitRunnerConfig struct {
	Runner           *RunnerReference `json:"runner"`
	EncodedJITConfig string           `json:"encodedJITConfig"`
}
