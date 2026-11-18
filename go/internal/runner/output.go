package runner

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"example.org/chare/internal/bench"
)

type sample struct {
	CaseID string
	Config bench.Config
	Value  bench.Measurement
}

func writeJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	// The files live in an exclusively created run directory. Windows does not
	// replace an existing target with Rename, so replace only this exact file.
	if err = os.Rename(tmp, path); err == nil {
		return nil
	}
	if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
		return removeErr
	}
	return os.Rename(tmp, path)
}

func newCSV(path string, header []string) (*os.File, *csv.Writer, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, nil, err
	}
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		f.Close()
		return nil, nil, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, w, nil
}

func flushCSV(f *os.File, w *csv.Writer) error {
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return f.Sync()
}

func measurementRow(runID string, s sample) []string {
	c, v := s.Config, s.Value
	return []string{runID, s.CaseID, strconv.Itoa(c.Capacity), strconv.Itoa(c.Attributes), strconv.Itoa(c.Replicate), strconv.Itoa(c.Revocations), strconv.Itoa(c.Acquisitions), v.Scheme, v.Operation, v.Mode, strconv.FormatInt(v.DurationNS, 10), strconv.FormatInt(v.Bytes, 10), strconv.FormatInt(v.SourceOps, 10), strconv.FormatInt(v.Pairings, 10), strconv.Itoa(v.Count), v.Detail}
}

func writeSummary(path string, rows []sample) error {
	type key struct {
		N, M, R, A       int
		Scheme, Op, Mode string
	}
	groups := make(map[key][]bench.Measurement)
	for _, s := range rows {
		k := key{s.Config.Capacity, s.Config.Attributes, s.Config.Revocations, s.Config.Acquisitions, s.Value.Scheme, s.Value.Operation, s.Value.Mode}
		groups[k] = append(groups[k], s.Value)
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.N != b.N {
			return a.N < b.N
		}
		if a.M != b.M {
			return a.M < b.M
		}
		if a.R != b.R {
			return a.R < b.R
		}
		if a.A != b.A {
			return a.A < b.A
		}
		if a.Scheme != b.Scheme {
			return a.Scheme < b.Scheme
		}
		if a.Op != b.Op {
			return a.Op < b.Op
		}
		return a.Mode < b.Mode
	})
	f, w, err := newCSV(path, []string{"capacity", "attributes", "revocations", "acquisitions", "scheme", "operation", "mode", "sample_count", "duration_sample_count", "duration_mean_ns", "duration_median_ns", "duration_min_ns", "duration_max_ns", "duration_p95_ns", "bytes_mean", "source_ops_mean", "pairings_mean", "operation_count_mean"})
	if err != nil {
		return err
	}
	defer f.Close()
	for _, k := range keys {
		values := groups[k]
		durations := make([]int64, 0, len(values))
		var totalTime, totalBytes, totalSource, totalPair, totalCount float64
		for _, v := range values {
			if !strings.Contains(v.Detail, "no timing sample") {
				durations = append(durations, v.DurationNS)
				totalTime += float64(v.DurationNS)
			}
			totalBytes += float64(v.Bytes)
			totalSource += float64(v.SourceOps)
			totalPair += float64(v.Pairings)
			totalCount += float64(v.Count)
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		n := len(values)
		mean := func(x float64) string { return strconv.FormatFloat(x/float64(n), 'f', 3, 64) }
		// A byte-only observation is not a measured zero-nanosecond operation.
		timing := make([]string, 5)
		nt := len(durations)
		if nt > 0 {
			median := float64(durations[nt/2])
			if nt%2 == 0 {
				median = (float64(durations[nt/2-1]) + float64(durations[nt/2])) / 2
			}
			timing = []string{strconv.FormatFloat(totalTime/float64(nt), 'f', 3, 64), strconv.FormatFloat(median, 'f', 3, 64), strconv.FormatInt(durations[0], 10), strconv.FormatInt(durations[nt-1], 10), strconv.FormatInt(durations[int(math.Ceil(.95*float64(nt)))-1], 10)}
		}
		row := []string{strconv.Itoa(k.N), strconv.Itoa(k.M), strconv.Itoa(k.R), strconv.Itoa(k.A), k.Scheme, k.Op, k.Mode, strconv.Itoa(n), strconv.Itoa(nt)}
		row = append(row, timing...)
		row = append(row, mean(totalBytes), mean(totalSource), mean(totalPair), mean(totalCount))
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return flushCSV(f, w)
}

func packageResults(dir string) (string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected result symlink: %s", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "SHA256SUMS" || rel == "return.zip" || rel == "return.zip.sha256" || strings.HasSuffix(rel, ".tmp") {
			return nil
		}
		paths = append(paths, rel)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	var sums strings.Builder
	for _, rel := range paths {
		h, err := hashFile(filepath.Join(dir, rel))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&sums, "%s  %s\n", h, filepath.ToSlash(rel))
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0600); err != nil {
		return "", err
	}
	paths = append(paths, "SHA256SUMS")
	archive := filepath.Join(dir, "return.zip")
	f, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	z := zip.NewWriter(f)
	for _, rel := range paths {
		if err := addArchiveFile(z, filepath.Join(dir, rel), filepath.ToSlash(rel)); err != nil {
			z.Close()
			f.Close()
			return "", err
		}
	}
	if err := z.Close(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	h, err := hashFile(archive)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(archive+".sha256", []byte(h+"  return.zip\n"), 0600); err != nil {
		return "", err
	}
	return archive, nil
}

func addArchiveFile(z *zip.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = name
	header.Method = zip.Deflate
	w, err := z.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
