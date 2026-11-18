// Run this main function in GoLand. It tests the complete module before running
// the existing batch entry point. The launcher itself uses no native libraries.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"example.org/chare/internal/projectpath"
)

type options struct {
	profile, config, params, out string
	timeout                      time.Duration
}

const defaultTimeout = 10 * time.Minute

func (o options) batchArgs() ([]string, error) {
	if o.profile != "sanity" && o.profile != "paper" {
		return nil, fmt.Errorf("unknown profile %q; use sanity or paper", o.profile)
	}
	config := o.config
	if config == "" {
		config = filepath.Join("config", o.profile+".json")
	}
	if o.timeout < 0 {
		return nil, errors.New("timeout must be positive; zero selects the 10-minute default")
	}
	a := []string{"-config", config, "-out", o.out}
	if o.params != "" {
		a = append(a, "-params", o.params)
	}
	return a, nil
}

type commandRunner func(context.Context, string, string, []string, io.Writer) error

// A failed or interrupted test gate never starts a batch. Commands are passed as
// argument arrays: spaces in paths do not require a shell or manual quoting.
func pipeline(ctx context.Context, root, goPath, batchPath string, o options, logs, console io.Writer, run commandRunner) error {
	args, err := o.batchArgs()
	if err != nil {
		return err
	}
	limit := o.timeout
	if limit == 0 {
		limit = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	out := io.MultiWriter(console, logs)
	steps := []struct {
		executable string
		args       []string
	}{
		{goPath, []string{"test", "-mod=vendor", "./...", "-count=1"}},
		{goPath, []string{"build", "-mod=vendor", "-o", batchPath, "."}},
		{batchPath, args},
	}
	for i, step := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		fmt.Fprintf(out, "\n[%d/3] %s %s\n", i+1, step.executable, strings.Join(step.args, " "))
		if err := run(ctx, root, step.executable, step.args, out); err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("launcher stopped: %w; completed case files are retained, but the active case and batch may be incomplete", ctx.Err())
			}
			if i == 0 {
				return fmt.Errorf("functional tests failed; no batch started: %w", err)
			}
			if i == 1 {
				return fmt.Errorf("build failed; no batch started: %w", err)
			}
			return fmt.Errorf("batch did not fully pass; retain its raw result directory: %w", err)
		}
	}
	return nil
}

// Execute the compiled batch directly: killing `go run` alone can leave its
// native child running. A deadline stops this actual measurement process.
func execute(ctx context.Context, dir, executable string, args []string, output io.Writer) error {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = 2 * time.Second
	return cmd.Run()
}

func launch(ctx context.Context, o options) error {
	root, err := projectpath.Root()
	if err != nil {
		return err
	}
	if _, err := o.batchArgs(); err != nil {
		return err
	}
	goName := "go"
	if runtime.GOOS == "windows" {
		goName += ".exe"
	}
	goPath := filepath.Join(runtime.GOROOT(), "bin", goName)
	if _, e := os.Stat(goPath); e != nil {
		goPath, err = exec.LookPath(goName)
		if err != nil {
			return fmt.Errorf("Go SDK executable unavailable: %w", err)
		}
	}
	logParent := filepath.Join(root, "build", "goland-runs")
	if err := os.MkdirAll(logParent, 0700); err != nil {
		return err
	}
	logDir, err := os.MkdirTemp(logParent, time.Now().UTC().Format("20060102T150405Z")+"-")
	if err != nil {
		return err
	}
	resultRoot, err := projectpath.OutputRoot(o.out)
	if err != nil {
		return err
	}
	publicLogDir := filepath.Join(resultRoot, "_launches", filepath.Base(logDir))
	if err := os.MkdirAll(publicLogDir, 0700); err != nil {
		return err
	}
	logFile, err := os.Create(filepath.Join(publicLogDir, "launcher.log"))
	if err != nil {
		return err
	}
	defer logFile.Close()
	if o.timeout == 0 {
		o.timeout = defaultTimeout
	}
	output := io.MultiWriter(os.Stdout, logFile)
	fmt.Fprintf(output, "CHARE module: %s\nLauncher log: %s\nTime budget: %s (tests, build, and batch).\n", root, logFile.Name(), o.timeout)
	fmt.Fprintln(output, "Full functional tests run first. Completed cases are checkpointed; a timeout is NOT a completed batch.")
	fmt.Fprintln(output, "Curve size configurations are not calibrated security levels.")
	batchName := "chare-batch"
	if runtime.GOOS == "windows" {
		batchName += ".exe"
	}
	started := time.Now().UTC()
	err = pipeline(ctx, root, goPath, filepath.Join(logDir, batchName), o, logFile, os.Stdout, execute)
	state := map[string]any{"schema": "chare-launch-status-v1", "started_utc": started.Format(time.RFC3339Nano), "finished_utc": time.Now().UTC().Format(time.RFC3339Nano), "timeout_seconds": o.timeout.Seconds(), "profile": o.profile, "config_override": o.config, "status": "passed"}
	if err != nil {
		state["status"], state["error"] = "failed_or_incomplete", err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			state["status"] = "timed_out"
		}
		fmt.Fprintln(output, "FAILED:", err)
	} else {
		fmt.Fprintln(output, "PASSED: functional gate and configured batch")
	}
	data, encodeErr := json.MarshalIndent(state, "", "  ")
	if encodeErr != nil {
		return errors.Join(err, encodeErr)
	}
	return errors.Join(err, os.WriteFile(filepath.Join(publicLogDir, "status.json"), append(data, '\n'), 0600))
}

func main() {
	var o options
	flag.StringVar(&o.profile, "profile", "paper", "paper (nine-case benchmark grid) or sanity (small validation grid)")
	flag.DurationVar(&o.timeout, "timeout", defaultTimeout, "wall-time budget for tests, build and batch; unfinished cases are not successful measurements")
	flag.StringVar(&o.config, "config", "", "optional JSON configuration, relative to CHARE module root")
	flag.StringVar(&o.params, "params", "", "optional trusted Type-A public parameter file")
	flag.StringVar(&o.out, "out", "results", "result parent directory, relative to CHARE module root")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments; use -help")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := launch(ctx, o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
