package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"example.org/chare/internal/runner"
)

func main() {
	var options runner.Options
	flag.StringVar(&options.ConfigPath, "config", "", "JSON configuration; omitted uses the small built-in sanity grid")
	flag.StringVar(&options.ParametersPath, "params", "", "existing public Type-A parameter file; overrides the configuration")
	flag.StringVar(&options.OutputRoot, "out", "results", "result directory relative to CHARE source root; absolute paths are also accepted")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments; use -help")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	summary, err := runner.Run(ctx, options)
	if summary.Directory != "" {
		fmt.Printf("Results: %s\n", summary.Directory)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Run did not fully pass:", err)
		os.Exit(1)
	}
	fmt.Printf("Completed: %d passed cases. Return bundle: %s\n", summary.Passed, summary.Archive)
}
