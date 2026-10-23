package scaleset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type scalesetError string

func (e scalesetError) Error() string {
	return string(e)
}

var (
	RunnerNotFoundError           = scalesetError("runner not found")
	RunnerExistsError             = scalesetError("runner exists")
	JobStillRunningError          = scalesetError("job still running")
	MessageQueueTokenExpiredError = scalesetError("message queue token expired")
	// Top-level errors carrying the HTTP status code meanings.
	BadRequestError   = scalesetError("bad request")
	NotFoundError     = scalesetError("not found")
	UnauthorizedError = scalesetError("unauthorized")
	ConflictError     = scalesetError("conflict")

	// MaxElapsedExceededError reports that a request ran out of its
	// RetryConfig.MaxElapsed budget while an attempt, or the read of its
	// response, was still in progress. It wraps context.DeadlineExceeded, so
	// errors.Is matches either.
	MaxElapsedExceededError error = maxElapsedError{}
)

type maxElapsedError struct{}

func (maxElapsedError) Error() string { return "retry budget MaxElapsed exceeded" }

func (maxElapsedError) Unwrap() error { return context.DeadlineExceeded }

const (
	headerRetryAfter         = "Retry-After"
	headerRateLimitRemaining = "X-RateLimit-Remaining"
	headerRateLimitReset     = "X-RateLimit-Reset"
)

var secondaryRateLimitPattern = regexp.MustCompile(`(?i)\bsecondary rate\b`)

// RateLimitKind tells which kind of rate limit rejected a request.
type RateLimitKind int

const (
	// RateLimitPrimary means X-RateLimit-Remaining: 0 without a secondary-limit message.
	RateLimitPrimary RateLimitKind = iota + 1
	// RateLimitSecondary covers all other rate-limited responses.
	RateLimitSecondary
)

func (k RateLimitKind) String() string {
	switch k {
	case RateLimitPrimary:
		return "primary"
	case RateLimitSecondary:
		return "secondary"
	default:
		return "RateLimitKind(" + strconv.Itoa(int(k)) + ")"
	}
}

// RateLimitError reports rate-limited responses; detect it with errors.As.
// It covers 429s and 403s with Retry-After, X-RateLimit-Remaining: 0,
// or a secondary-limit message.
type RateLimitError struct {
	// Kind tells a spent primary rate limit apart from any other rate limit.
	Kind RateLimitKind

	// StatusCode is the HTTP status of the rejected response.
	StatusCode int

	// RetryAfter comes from Retry-After, then X-RateLimit-Reset if quota is spent.
	// Zero means no usable delay or an explicit zero. For secondary limits,
	// fall back to at least one minute with bounded exponential retries.
	RetryAfter time.Duration

	// Reset is when the rate limit window resets, from X-RateLimit-Reset.
	// It is the zero time when the header is absent or invalid.
	Reset time.Time

	// Retries is the number of rate-limited retries the client already made
	// for this request before this response, of either kind. It is zero when
	// the first rate-limited response was the last one.
	Retries int

	// err preserves the request/response error and its context.
	err error
}

func (e *RateLimitError) Error() string {
	msg := "rate limited"
	if e.RetryAfter > 0 {
		msg += " (retry after " + e.RetryAfter.String() + ")"
	}
	if e.err != nil {
		msg += ": " + e.err.Error()
	}
	return msg
}

func (e *RateLimitError) Unwrap() error {
	return e.err
}

// rateLimitFromResponse classifies the status, headers, and response message.
// now anchors retry hints; the caller attaches the underlying error.
func rateLimitFromResponse(resp *http.Response, message string, now time.Time) (*RateLimitError, bool) {
	if resp == nil {
		return nil, false
	}

	primary := resp.Header.Get(headerRateLimitRemaining) == "0"
	secondary := secondaryRateLimitPattern.MatchString(message)

	switch resp.StatusCode {
	case http.StatusTooManyRequests:
	case http.StatusForbidden:
		if !primary && !secondary && resp.Header.Get(headerRetryAfter) == "" {
			return nil, false
		}
	default:
		return nil, false
	}

	rl := &RateLimitError{
		Kind:       RateLimitSecondary,
		StatusCode: resp.StatusCode,
		Reset:      parseRateLimitReset(resp.Header.Get(headerRateLimitReset)),
	}
	if primary && !secondary {
		rl.Kind = RateLimitPrimary
	}

	if wait, ok := parseRetryAfter(resp.Header.Get(headerRetryAfter), now); ok {
		rl.RetryAfter = wait
	} else if primary && !rl.Reset.IsZero() {
		if wait, ok := durationUntil(rl.Reset, now); ok {
			rl.RetryAfter = wait
		}
	}

	return rl, true
}

// parseRateLimitReset reads X-RateLimit-Reset, the reset time in UTC epoch
// seconds. It returns the zero time for a missing or invalid value.
func parseRateLimitReset(value string) time.Time {
	if value == "" {
		return time.Time{}
	}

	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}
	}

	return time.Unix(seconds, 0)
}

type actionsExceptionError struct {
	ExceptionName string `json:"typeName,omitempty"`
	Message       string `json:"message,omitempty"`
}

func (e actionsExceptionError) Error() string {
	return fmt.Sprintf("%s: %s", e.ExceptionName, e.Message)
}

// newRequestResponseError creates a detailed error message based on the HTTP request and response,
// including parsing the response body for known error formats.
//
// The sendRequest already parses errors using this method, so use this error if the client doesn't
// return an error, but the error is happening on the application logic level.
//
// Prefer creating errors using this function instead of manually constructing error messages since it automatically
// includes useful metadata like activity IDs and request IDs, and handles well-known error cases.
func newRequestResponseError(req *http.Request, resp *http.Response, err error) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "request %s %s failed", req.Method, req.URL.String())

	if resp == nil {
		return fmt.Errorf("%s: %w", sb.String(), err)
	}

	sb.WriteRune('(')
	fmt.Fprintf(&sb, "status=%q", resp.Status)
	if resp.Header.Get(headerActionsActivityID) != "" {
		fmt.Fprintf(&sb, ", activity_id=%q", resp.Header.Get(headerActionsActivityID))
	}

	if resp.Header.Get(headerGitHubRequestID) != "" {
		fmt.Fprintf(&sb, ", github_request_id=%q", resp.Header.Get(headerGitHubRequestID))
	}
	sb.WriteRune(')')

	if resp.Body == nil || resp.ContentLength == 0 {
		return wrapResponseErrorType(resp, "", fmt.Errorf("%s: %w: unknown error", sb.String(), err))
	}

	body, bodyErr := io.ReadAll(resp.Body)
	if bodyErr != nil {
		return wrapResponseErrorType(resp, "", fmt.Errorf("%s: %w: failed to read error response body: %w", sb.String(), err, bodyErr))
	}
	if len(body) == 0 {
		return wrapResponseErrorType(resp, "", fmt.Errorf("%s: %w: unknown error", sb.String(), err))
	}

	var scalesetErr scalesetError
	if errors.As(err, &scalesetErr) {
		return wrapResponseErrorType(resp, string(body), fmt.Errorf("%s: %w: %s", sb.String(), err, string(body)))
	}

	contentType := resp.Header.Get("Content-Type")
	if len(contentType) > 0 && strings.Contains(contentType, "text/plain") {
		return wrapResponseErrorType(resp, string(body), fmt.Errorf("%s: %w: %s", sb.String(), err, string(body)))
	}

	var exception actionsExceptionError
	if err := json.Unmarshal(body, &exception); err != nil {
		return wrapResponseErrorType(resp, "", fmt.Errorf("%s: %w: failed to unmarshal error response body: %q", sb.String(), err, string(body)))
	}

	switch {
	case strings.Contains(exception.ExceptionName, "AgentExistsException"):
		return wrapResponseErrorType(resp, exception.Message, fmt.Errorf("%s: %w: %s", sb.String(), RunnerExistsError, exception.Message))
	case strings.Contains(exception.ExceptionName, "AgentNotFoundException"):
		return wrapResponseErrorType(resp, exception.Message, fmt.Errorf("%s: %w: %s", sb.String(), RunnerNotFoundError, exception.Message))
	case strings.Contains(exception.ExceptionName, "JobStillRunningException"):
		return wrapResponseErrorType(resp, exception.Message, fmt.Errorf("%s: %w: %s", sb.String(), JobStillRunningError, exception.Message))
	default:
		return wrapResponseErrorType(resp, exception.Message, fmt.Errorf("%s: %w: %w", sb.String(), err, exception))
	}
}

func wrapResponseErrorType(resp *http.Response, message string, err error) error {
	if rl, ok := rateLimitFromResponse(resp, message, time.Now()); ok {
		rl.Retries = rateLimitRetriesOf(resp)
		rl.err = err
		return rl
	}

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %w", BadRequestError, err)
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %w", UnauthorizedError, err)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %w", NotFoundError, err)
	case http.StatusConflict:
		return fmt.Errorf("%w: %w", ConflictError, err)
	default:
		return err
	}
}
