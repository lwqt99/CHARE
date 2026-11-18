package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"example.org/chare/internal/projectpath"
)

func TestFailedGateNeverStartsBatch(t *testing.T) {
	calls := 0
	err := pipeline(context.Background(), t.TempDir(), "go", "batch", options{profile: "paper"}, io.Discard, io.Discard,
		func(_ context.Context, _, _ string, args []string, _ io.Writer) error {
			calls++
			if args[0] != "test" {
				t.Fatal("started batch before tests")
			}
			return errors.New("native library missing")
		})
	if calls != 1 || err == nil || !strings.Contains(err.Error(), "no batch started") {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestPassedGateUsesOriginalConfigAndPaths(t *testing.T) {
	calls := 0
	root := filepath.Join(t.TempDir(), "path with spaces")
	o := options{profile: "paper", config: "config/custom grid.json", params: "public params.txt", out: "new results"}
	err := pipeline(context.Background(), root, "go", "batch", o, io.Discard, io.Discard,
		func(_ context.Context, dir, executable string, args []string, _ io.Writer) error {
			calls++
			if dir != root {
				t.Fatal("working directory changed")
			}
			if calls <= 2 {
				if executable != "go" {
					t.Fatal("test/build must use Go")
				}
				return nil
			}
			if executable != "batch" {
				t.Fatal("batch must be executed directly")
			}
			want := []string{"-config", o.config, "-out", o.out, "-params", o.params}
			if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
				t.Fatalf("arguments: %q", args)
			}
			return nil
		})
	if err != nil || calls != 3 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestCancelledGateDoesNotLaunchBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := pipeline(ctx, t.TempDir(), "go", "batch", options{profile: "sanity"}, io.Discard, io.Discard,
		func(_ context.Context, _, _ string, _ []string, _ io.Writer) error { calls++; cancel(); return nil })
	if calls != 1 || !errors.Is(err, context.Canceled) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestFindRootFromParentAndNestedWorkingDirectory(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "CHARE")
	if err := os.MkdirAll(filepath.Join(root, "cmd", "goland"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.org/chare\n\ngo 1.23\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, start := range []string{parent, root, filepath.Join(root, "cmd", "goland")} {
		got, err := projectpath.FindRoot(start)
		if err != nil || got != root {
			t.Fatalf("root(%s)=%s, %v", start, got, err)
		}
	}
}

func TestInvalidProfileDoesNotStartCommands(t *testing.T) {
	err := pipeline(context.Background(), t.TempDir(), "go", "batch", options{profile: "invalid"}, io.Discard, io.Discard,
		func(context.Context, string, string, []string, io.Writer) error {
			t.Fatal("invalid profile executed")
			return nil
		})
	if err == nil {
		t.Fatal("accepted invalid profile")
	}
}

func TestFailedBuildNeverStartsNativeBatch(t *testing.T) {
	calls := 0
	err := pipeline(context.Background(), t.TempDir(), "go", "batch", options{profile: "paper"}, io.Discard, io.Discard,
		func(_ context.Context, _, executable string, args []string, _ io.Writer) error {
			calls++
			if executable != "go" {
				t.Fatal("native batch started after a failed build")
			}
			if args[0] == "build" {
				return errors.New("build failed")
			}
			return nil
		})
	if calls != 2 || err == nil || !strings.Contains(err.Error(), "build failed; no batch started") {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestBudgetStopsPipelineWithoutStartingNextStage(t *testing.T) {
	calls := 0
	err := pipeline(context.Background(), t.TempDir(), "go", "batch", options{profile: "paper", timeout: 20 * time.Millisecond}, io.Discard, io.Discard,
		func(ctx context.Context, _, _ string, _ []string, _ io.Writer) error {
			calls++
			<-ctx.Done()
			return ctx.Err()
		})
	if calls != 1 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestDeadlineChild(t *testing.T) {
	dir := os.Getenv("CHARE_LAUNCHER_TIMEOUT_HELPER")
	if dir == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "completed-case.json"), []byte(`{"status":"passed"}`), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(15 * time.Second)
	if err := os.WriteFile(filepath.Join(dir, "should-not-finish"), []byte("done"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDirectProcessDeadlineRetainsCheckpoint(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CHARE_LAUNCHER_TIMEOUT_HELPER", dir)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	err := execute(ctx, dir, os.Args[0], []string{"-test.run=^TestDeadlineChild$"}, io.Discard)
	if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("err=%v context=%v", err, ctx.Err())
	}
	if time.Since(started) > 6*time.Second {
		t.Fatal("deadline failed to stop child promptly")
	}
	if _, err := os.Stat(filepath.Join(dir, "completed-case.json")); err != nil {
		t.Fatal("lost completed checkpoint", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "should-not-finish")); !os.IsNotExist(err) {
		t.Fatal("child unexpectedly completed")
	}
}
