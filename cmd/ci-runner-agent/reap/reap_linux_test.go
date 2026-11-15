//go:build linux

package reap

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func setSubreaper(t *testing.T) {
	t.Helper()

	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, 36 /* PR_SET_CHILD_SUBREAPER */, 1, 0)
	if errno != 0 {
		t.Skipf("PR_SET_CHILD_SUBREAPER unavailable: %v", syscall.Errno(errno))
	}
}

func script(t *testing.T, body string) *exec.Cmd {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	return exec.Command(path)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunReapsOrphanedProcesses(t *testing.T) {
	setSubreaper(t)

	cmd := script(t, `
( sleep 30 & echo $! > "$dir/pid" )
kill -9 "$(cat "$dir/pid")"
sleep 0.5
if kill -0 "$(cat "$dir/pid")" 2>/dev/null; then
  exit 3
fi
exit 0
`)

	dir := filepath.Dir(cmd.Path)
	cmd.Env = append(os.Environ(), "dir="+dir)

	got := Run(discardLogger(), cmd, make(chan os.Signal, 1))
	if got != 0 {
		t.Fatalf("Run returned %d, want 0: the orphan stayed a zombie", got)
	}
}

func TestRunReturnsTheExitStatus(t *testing.T) {
	setSubreaper(t)

	cmd := script(t, "exit 7")

	got := Run(discardLogger(), cmd, make(chan os.Signal, 1))
	if got != 7 {
		t.Fatalf("exit code: got %d, want 7", got)
	}
}

func TestRunReportsASignalAs128PlusSignal(t *testing.T) {
	setSubreaper(t)

	cmd := script(t, "kill -TERM $$")

	got := Run(discardLogger(), cmd, make(chan os.Signal, 1))
	if got != 143 {
		t.Fatalf("signal exit code: got %d, want 143", got)
	}
}

func TestRunForwardsSignals(t *testing.T) {
	setSubreaper(t)

	cmd := script(t, `trap 'exit 5' TERM; echo $$ > "$dir/ready"; while :; do sleep 0.1; done`)

	dir := filepath.Dir(cmd.Path)
	cmd.Env = append(os.Environ(), "dir="+dir)

	sigs := make(chan os.Signal, 1)
	done := make(chan int, 1)

	go func() {
		done <- Run(discardLogger(), cmd, sigs)
	}()

	ready := filepath.Join(dir, "ready")
	// A failed run must not leave the script looping after the test.
	t.Cleanup(func() {
		if b, err := os.ReadFile(ready); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ready file never written")
		}
		time.Sleep(20 * time.Millisecond)
	}

	sigs <- syscall.SIGTERM

	select {
	case got := <-done:
		if got != 5 {
			t.Fatalf("exit code after SIGTERM: got %d, want 5", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after SIGTERM")
	}
}

func TestRunFailsWhenTheCommandCannotStart(t *testing.T) {
	cmd := exec.Command(filepath.Join(t.TempDir(), "missing"))

	got := Run(discardLogger(), cmd, make(chan os.Signal, 1))
	if got != 1 {
		t.Fatalf("start failure: got %d, want 1", got)
	}
}

func waitStatus(t *testing.T, args ...string) syscall.WaitStatus {
	t.Helper()

	cmd := exec.Command("sh", args...)
	err := cmd.Run()
	if cmd.ProcessState == nil {
		t.Fatalf("sh %q: %v", args, err)
	}

	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("ProcessState.Sys() is not a syscall.WaitStatus")
	}

	return ws
}

func TestCode(t *testing.T) {
	if got := Code(waitStatus(t, "-c", "exit 4")); got != 4 {
		t.Fatalf("exit code: got %d, want 4", got)
	}

	if got := Code(waitStatus(t, "-c", "kill -KILL $$")); got != 137 {
		t.Fatalf("signal exit code: got %d, want 137", got)
	}
}
