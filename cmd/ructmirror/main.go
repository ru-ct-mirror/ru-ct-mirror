// Command ructmirror mirrors and verifies the Russian national CT logs.
//
//	ructmirror sync   [-root DIR] [-only operator/shard] [-batch N]
//	ructmirror verify [-root DIR] [-only operator/shard]
//
// DIR is the repository root: it must contain logs.json, roots/ and data/.
//
// Exit status: 0 when everything verified, 2 when a log or the log list
// failed verification (evidence was written), 1 for any other error such as
// an unreachable log.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ru-ct-mirror/ru-ct-mirror/internal/config"
	"github.com/ru-ct-mirror/ru-ct-mirror/internal/ctclient"
	"github.com/ru-ct-mirror/ru-ct-mirror/internal/loglist"
	"github.com/ru-ct-mirror/ru-ct-mirror/internal/mirror"
	"github.com/ru-ct-mirror/ru-ct-mirror/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	root := fs.String("root", ".", "repository root (contains logs.json, roots/, data/)")
	only := fs.String("only", "", "limit to one log, as operator/shard")
	batch := fs.Uint64("batch", 256, "entries per get-entries request")
	fs.Parse(os.Args[2:])

	cfg, err := config.Load(filepath.Join(*root, "logs.json"))
	fatal(err)
	logs := cfg.Logs
	if *only != "" {
		logs = nil
		for _, l := range cfg.Logs {
			if l.Name() == *only {
				logs = append(logs, l)
			}
		}
		if len(logs) == 0 {
			fatal(fmt.Errorf("no log named %q in logs.json", *only))
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var failures, alerts int
	switch os.Args[1] {
	case "sync":
		cl, err := ctclient.New(filepath.Join(*root, "roots"))
		fatal(err)
		if *only == "" {
			drift, err := snapshotLogList(ctx, cl, cfg, *root)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				failures++
			}
			if drift {
				alerts++
			}
		}
		for _, l := range logs {
			if l.Disabled {
				continue
			}
			st, err := store.Open(filepath.Join(*root, "data", l.Operator, l.Shard))
			fatal(err)
			res, err := mirror.Sync(ctx, cl, l, st, mirror.Options{Batch: *batch, Log: os.Stderr})
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				var a *mirror.Alert
				if errors.As(err, &a) {
					alerts++
				} else {
					failures++
				}
				continue
			}
			fmt.Fprintf(os.Stderr, "%s: ok, size %d -> %d, %d chunk(s), new STH: %v\n", l.Name(), res.OldSize, res.NewSize, res.ChunksWritten, res.NewSTH)
		}
	case "verify":
		for _, l := range logs {
			dir := filepath.Join(*root, "data", l.Operator, l.Shard)
			if _, err := os.Stat(dir); l.Disabled && os.IsNotExist(err) {
				continue
			}
			st, err := store.Open(dir)
			fatal(err)
			if err := mirror.Verify(l, st); err != nil {
				fmt.Fprintln(os.Stderr, "FAIL", err)
				alerts++
				continue
			}
			state, _, _ := st.LoadState()
			fmt.Fprintf(os.Stderr, "%s: ok, %d entries, root %s\n", l.Name(), state.TreeSize, state.RootHash)
		}
	default:
		usage()
	}
	switch {
	case alerts > 0:
		fmt.Fprintf(os.Stderr, "%d verification failure(s), %d other error(s)\n", alerts, failures)
		os.Exit(2)
	case failures > 0:
		fmt.Fprintf(os.Stderr, "%d error(s)\n", failures)
		os.Exit(1)
	}
}

// snapshotLogList downloads ctlog.json into loglist/ and reports drift from
// logs.json. drift is true when the published list disagrees with logs.json,
// which is a verification failure rather than an operational error.
func snapshotLogList(ctx context.Context, cl *ctclient.Client, cfg *config.File, root string) (drift bool, err error) {
	if cfg.LogListURL == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	b, err := cl.GetJSON(ctx, cfg.LogListURL)
	if err != nil {
		return false, fmt.Errorf("log list: %w", err)
	}
	dir := filepath.Join(root, "loglist")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(dir, "ctlog.json"), b, 0o644); err != nil {
		return false, err
	}
	d, err := loglist.Compare(b, cfg)
	if err != nil {
		return false, fmt.Errorf("log list: %w", err)
	}
	if d.Empty() {
		fmt.Fprintln(os.Stderr, "log list: ctlog.json agrees with logs.json")
		return false, nil
	}
	var errs []error
	for _, u := range d.Unknown {
		errs = append(errs, fmt.Errorf("ALERT log list: log not in logs.json: %s", u))
	}
	for _, c := range d.Changed {
		errs = append(errs, fmt.Errorf("ALERT log list: key changed: %s", c))
	}
	return true, errors.Join(errs...)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ructmirror sync|verify [-root DIR] [-only operator/shard] [-batch N]")
	os.Exit(2)
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
