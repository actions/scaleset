package scaleset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RequestResponseError describes a failed HTTP request or an unusable response.
// Use errors.As to inspect it and errors.Is to check its underlying causes,
// including the status and domain errors defined in this package.
type RequestResponseError struct {
	// Response is a snapshot of the failed attempt's response, or nil if none
	// is available (including cancellation between attempts).
	// Its Body is an independent, in-memory reader containing the original bytes
	// returned by the HTTP client (only the bytes received on a read failure).
	// The network body has already been closed. Headers, trailers, and other
	// response metadata are retained; Request may contain credentials.
	Response *http.Response

	// Err includes the original cause and any recognized HTTP/API errors.
	Err error
}

func (e *RequestResponseError) Error() string {
	if e.Err == nil {
		return "HTTP request failed"
	}
	return e.Err.Error()
}

func (e *RequestResponseError) Unwrap() error {
	return e.Err
}

var errMissingResponse = errors.New("HTTP client returned a nil response without an error")

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
	// Zero means no usable delay or an explicit zero; the SDK does not set a
	// fallback here. Callers scheduling retries must choose a positive fallback,
	// for example at least one minute for secondary limits.
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

func redactedURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	copy := *u
	copy.User = nil
	copy.RawQuery, copy.Fragment, copy.RawFragment = "", "", ""
	copy.ForceQuery = false
	return copy.String()
}

// newRequestResponseError retains the response and cause, adding known API error
// classifications without dumping raw response bodies or request credentials.
func newRequestResponseError(req *http.Request, resp *http.Response, err error) error {
	body, bodyErr := bufferResponseBody(resp)
	if bodyErr != nil {
		err = errors.Join(err, bodyErr)
	}

	var snapshot *http.Response
	if resp != nil {
		copy := *resp
		copy.Header = resp.Header.Clone()
		copy.Trailer = resp.Trailer.Clone()
		copy.Body = io.NopCloser(bytes.NewReader(body))
		if copy.Request == nil {
			copy.Request = req
		}
		snapshot = &copy
		if copy.Request != nil {
			req = copy.Request
		}
	}

	var sb strings.Builder
	sb.WriteString("request")
	if req != nil {
		fmt.Fprintf(&sb, " %s", req.Method)
		if req.URL != nil {
			fmt.Fprintf(&sb, " %s", redactedURL(req.URL))
		}
	}
	sb.WriteString(" failed")

	var message string
	if resp != nil {
		sb.WriteRune('(')
		fmt.Fprintf(&sb, "status=%q", resp.Status)
		if resp.Header.Get(headerActionsActivityID) != "" {
			fmt.Fprintf(&sb, ", activity_id=%q", resp.Header.Get(headerActionsActivityID))
		}
		if resp.Header.Get(headerGitHubRequestID) != "" {
			fmt.Fprintf(&sb, ", github_request_id=%q", resp.Header.Get(headerGitHubRequestID))
		}
		sb.WriteRune(')')
		if buffered, ok := resp.Body.(*bufferedResponseBody); ok && buffered.incomplete {
			body = nil
		}
		message, err = responseErrorCause(resp, body, err)
	}

	return &RequestResponseError{
		Response: snapshot,
		Err:      wrapResponseErrorType(resp, message, fmt.Errorf("%s: %w", sb.String(), err)),
	}
}

func responseErrorCause(resp *http.Response, body []byte, err error) (string, error) {
	// A successful response may contain tokens or JIT configuration, not an
	// API error. Do not reinterpret it when decoding or validation fails.
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return "", err
	}
	if len(body) == 0 {
		return "", fmt.Errorf("%w: unknown error", err)
	}

	var scalesetErr scalesetError
	if errors.As(err, &scalesetErr) {
		return string(body), err
	}

	var exception actionsExceptionError
	if parseErr := json.Unmarshal(trimByteOrderMark(body), &exception); parseErr != nil {
		if strings.Contains(resp.Header.Get("Content-Type"), "text/plain") {
			return string(body), err
		}
		return "", fmt.Errorf("%w: failed to unmarshal error response body: %w", err, parseErr)
	}

	switch {
	case strings.Contains(exception.ExceptionName, "AgentExistsException"):
		err = fmt.Errorf("%w: %w: %w", err, RunnerExistsError, exception)
	case strings.Contains(exception.ExceptionName, "AgentNotFoundException"):
		err = fmt.Errorf("%w: %w: %w", err, RunnerNotFoundError, exception)
	case strings.Contains(exception.ExceptionName, "JobStillRunningException"):
		err = fmt.Errorf("%w: %w: %w", err, JobStillRunningError, exception)
	case exception.ExceptionName != "" || exception.Message != "":
		err = fmt.Errorf("%w: %w", err, exception)
	}
	return exception.Message, err
}

func wrapResponseErrorType(resp *http.Response, message string, err error) error {
	if resp == nil {
		return err
	}
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
