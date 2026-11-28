// Package reap runs the GitHub Actions runner as the child of PID 1 of the
// runner container and reaps every other child meanwhile.
//
// Job processes orphaned by a kill are re-parented to PID 1. Without a
// reaper they stay zombies, still visible to kill(pid, 0), until the pod
// ends; ARC's bash reaped them. cmd.Wait is not used: wait4(-1) would steal
// its status.
package reap

import (
	"log/slog"
	"os"
	"os/exec"
	"syscall"
)

// Run starts cmd, forwards every signal received on sigs to it, and returns
// its exit code: the exit status, or 128+signal when a signal killed it.
func Run(log *slog.Logger, cmd *exec.Cmd, sigs <-chan os.Signal) int {
	if err := cmd.Start(); err != nil {
		log.Error("runner not started", "command", cmd.Path, "error", err)
		return 1
	}
	done := make(chan result, 1)
	go func() { done <- wait(cmd.Process.Pid) }()
	for {
		select {
		case s := <-sigs:
			_ = cmd.Process.Signal(s)
		case r := <-done:
			if r.err != nil {
				log.Error("runner failed", "error", r.err)
				return 1
			}
			return Code(r.status)
		}
	}
}

// Code is the exit code of a reaped process, as a shell reports it.
func Code(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

type result struct {
	status syscall.WaitStatus
	err    error
}

// wait reaps children until it reaps pid. The blocking wait4 is restarted
// by the kernel after a Go signal handler (SA_RESTART), so EINTR does not
// surface here.
func wait(pid int) result {
	for {
		var ws syscall.WaitStatus
		got, err := syscall.Wait4(-1, &ws, 0, nil)
		if err != nil {
			return result{err: err}
		}
		if got == pid {
			return result{status: ws}
		}
	}
}
