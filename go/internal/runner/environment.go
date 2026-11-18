package runner

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

func environment() map[string]any {
	data := map[string]any{
		"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
		"logical_cpus": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0),
		"protocol_execution":    "sequential; crypto/rand provider; no forced GC policy change",
		"pbc_go_binding_commit": "3e516ca0c5d64646fd1c3aeb1ecd41dacba1f0c6",
		"pbc_go_local_patch":    "Windows memstream temporary-file and buffer fix; see docs/VENDOR_PATCHES.md and actual source hashes",
		"native_pbc_version":    "not inferred from the Go wrapper; inspect linked-library metadata",
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		data["go_build_info"] = info
	}
	// Only a small explicit allowlist is recorded, never the full environment.
	vars := map[string]string{}
	for _, name := range []string{"CGO_ENABLED", "CC", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_LDFLAGS", "GOMAXPROCS", "GOGC"} {
		if value, ok := os.LookupEnv(name); ok {
			vars[name] = value
		}
	}
	data["build_environment_allowlist"] = vars
	data["gcc_version_if_available"] = boundedCommand("gcc", "--version")
	data["pbc_pkg_config"] = boundedCommand("pkg-config", "--modversion", "pbc")
	data["gmp_pkg_config"] = boundedCommand("pkg-config", "--modversion", "gmp")
	if runtime.GOOS == "linux" {
		data["kernel"] = boundedCommand("uname", "-a")
		data["cpu"] = boundedCommand("lscpu")
		if memory, err := os.ReadFile("/proc/meminfo"); err == nil {
			data["memory_info"] = string(memory)
		}
		if release, err := os.ReadFile("/etc/os-release"); err == nil {
			data["os_release"] = string(release)
		}
		if executable, err := os.Executable(); err == nil {
			data["linked_libraries"] = boundedCommand("ldd", executable)
		}
	}
	return data
}

func boundedCommand(name string, args ...string) map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if len(output) > 16384 {
		output = output[:16384]
	}
	result := map[string]string{"command": name + " " + strings.Join(args, " "), "output": strings.TrimSpace(string(output))}
	if err != nil {
		result["error"] = err.Error()
	}
	return result
}
