package userjobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/linux-temp-admin/internal/executil"
)

func isolateJobHelpers(t *testing.T) {
	t.Helper()
	oldLook, oldCombinedOutput, oldOutput := lookPath, combinedOutput, output
	oldCron, oldAt, oldSleep, oldProcRoot := cronSpoolDirectories, atSpoolDirectories, drainSleep, drainProcRoot
	t.Cleanup(func() {
		lookPath, combinedOutput, output = oldLook, oldCombinedOutput, oldOutput
		cronSpoolDirectories, atSpoolDirectories, drainSleep, drainProcRoot = oldCron, oldAt, oldSleep, oldProcRoot
	})
	root := t.TempDir()
	cronDir := filepath.Join(root, "cron")
	atDir := filepath.Join(root, "at")
	if err := os.Mkdir(cronDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(atDir, 0o700); err != nil {
		t.Fatal(err)
	}
	procDir := filepath.Join(root, "proc")
	if err := os.Mkdir(procDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cronSpoolDirectories = []string{cronDir}
	atSpoolDirectories = []string{atDir}
	drainProcRoot = procDir
}

func TestKnownCronSpoolLayouts(t *testing.T) {
	want := []string{
		"/var/spool/cron/crontabs",
		"/var/spool/cron",
		"/var/spool/cron/tabs",
	}
	if !reflect.DeepEqual(cronSpoolDirectories, want) {
		t.Fatalf("cronSpoolDirectories = %v, want %v", cronSpoolDirectories, want)
	}
}

func TestClearRejectsInvalidUIDBeforeInspectingJobs(t *testing.T) {
	isolateJobHelpers(t)
	lookPath = func(string) (string, error) {
		t.Fatal("invalid UID reached deferred-job tooling")
		return "", nil
	}
	invalidUIDs := []int{-1, 0}
	if strconv.IntSize >= 64 {
		reservedKernelID := uint64(^uint32(0))
		reserved := int(reservedKernelID)
		invalidUIDs = append(invalidUIDs, reserved, reserved+1)
	}
	for _, uid := range invalidUIDs {
		if err := Clear("xxvcc-a1", uid); err == nil || !strings.Contains(err.Error(), "invalid Linux account UID") {
			t.Fatalf("Clear uid=%d error = %v, want account-UID refusal", uid, err)
		}
	}
}

func TestClearRemovesCrontabAndOnlyMatchingUIDAtJobs(t *testing.T) {
	isolateJobHelpers(t)
	const name = "xxvcc-a1"
	cronPresent := true
	jobs := map[string]int{"7": 1001, "8": 2002}
	lookPath = func(command string) (string, error) {
		switch command {
		case "crontab", "at", "atq", "atrm":
			return "/mock/" + command, nil
		default:
			return "", exec.ErrNotFound
		}
	}
	output = func(command string, args []string, _ executil.Options) ([]byte, error) {
		switch command {
		case "atq":
			ids := make([]string, 0, len(jobs))
			for id := range jobs {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			return []byte(strings.Join(ids, " queued\n") + map[bool]string{true: " queued\n", false: ""}[len(ids) > 0]), nil
		case "at":
			uid, ok := jobs[args[1]]
			if !ok {
				return nil, errors.New("job disappeared")
			}
			return []byte(fmt.Sprintf("#!/bin/sh\n# atrun uid=%d gid=%d\n/bin/true\n", uid, uid)), nil
		default:
			return nil, fmt.Errorf("unexpected output command %s", command)
		}
	}
	var removed []string
	combinedOutput = func(command string, args []string, _ executil.Options) ([]byte, error) {
		switch command {
		case "crontab":
			switch args[2] {
			case "-r":
				cronPresent = false
				return nil, nil
			case "-l":
				if cronPresent {
					return []byte("* * * * * /bin/true\n"), nil
				}
				return []byte("no crontab for " + name + "\n"), errors.New("exit 1")
			default:
				return nil, fmt.Errorf("unexpected crontab action %q", args[2])
			}
		case "atrm":
			removed = append(removed, args[0])
			delete(jobs, args[0])
			return nil, nil
		default:
			return nil, fmt.Errorf("unexpected run command %s", command)
		}
	}

	if err := Clear(name, 1001); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{"7"}) {
		t.Fatalf("removed at jobs = %v, want only target job 7", removed)
	}
	if !reflect.DeepEqual(jobs, map[string]int{"8": 2002}) {
		t.Fatalf("unrelated at job changed: %v", jobs)
	}
}

func TestClearAtJobsUsesBoundedOwnerProbeForOversizedBodies(t *testing.T) {
	isolateJobHelpers(t)
	jobs := map[string]int{"7": 1001, "8": 2002}
	lookPath = func(command string) (string, error) {
		switch command {
		case "at", "atq", "atrm":
			return "/mock/" + command, nil
		default:
			return "", exec.ErrNotFound
		}
	}
	output = func(command string, args []string, opts executil.Options) ([]byte, error) {
		switch command {
		case "atq":
			ids := make([]string, 0, len(jobs))
			for id := range jobs {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			return []byte(strings.Join(ids, " queued\n") + map[bool]string{true: " queued\n", false: ""}[len(ids) > 0]), nil
		case "at":
			if opts.MaxOutput != atOwnerProbeLimit {
				t.Fatalf("at owner probe limit = %d, want %d", opts.MaxOutput, atOwnerProbeLimit)
			}
			uid, ok := jobs[args[1]]
			if !ok {
				return nil, errors.New("job disappeared")
			}
			return []byte(fmt.Sprintf("#!/bin/sh\n# atrun uid=%d gid=%d\n", uid, uid)),
				fmt.Errorf("%w (%d bytes)", executil.ErrOutputLimit, atOwnerProbeLimit)
		default:
			return nil, fmt.Errorf("unexpected output command %s", command)
		}
	}
	combinedOutput = func(command string, args []string, _ executil.Options) ([]byte, error) {
		if command != "atrm" {
			return nil, fmt.Errorf("unexpected command %s", command)
		}
		delete(jobs, args[0])
		return nil, nil
	}

	if err := clearAtJobs(1001); err != nil {
		t.Fatalf("clearAtJobs rejected an unrelated oversized body: %v", err)
	}
	if !reflect.DeepEqual(jobs, map[string]int{"8": 2002}) {
		t.Fatalf("jobs after cleanup = %v, want only unrelated job 8", jobs)
	}
}

func TestCrontabAbsentRetainsStderrDiagnostic(t *testing.T) {
	for _, diagnostic := range []string{
		"no crontab for xxvcc-a1",
		"crontab: can't open 'xxvcc-a1': No such file or directory",
	} {
		t.Run(diagnostic, func(t *testing.T) {
			isolateJobHelpers(t)
			const name = "xxvcc-a1"
			bin := t.TempDir()
			script := filepath.Join(bin, "crontab")
			body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' %q >&2\nexit 1\n", diagnostic)
			if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin)
			combinedOutput = executil.CombinedOutput

			absent, err := crontabAbsent(name)
			if err != nil {
				t.Fatal(err)
			}
			if !absent {
				t.Fatal("crontabAbsent = false, want stderr-only absence diagnostic to be recognized")
			}
		})
	}
}

func TestClearFailsClosedOnPartialOrMalformedAtInventory(t *testing.T) {
	t.Run("partial tools", func(t *testing.T) {
		isolateJobHelpers(t)
		lookPath = func(command string) (string, error) {
			if command == "atq" {
				return "/mock/atq", nil
			}
			return "", exec.ErrNotFound
		}
		if err := Clear("xxvcc-a1", 1001); err == nil || !strings.Contains(err.Error(), "partial at installation") {
			t.Fatalf("Clear error = %v, want partial-installation refusal", err)
		}
	})

	t.Run("missing owner header", func(t *testing.T) {
		isolateJobHelpers(t)
		lookPath = func(command string) (string, error) {
			if command == "at" || command == "atq" || command == "atrm" {
				return "/mock/" + command, nil
			}
			return "", exec.ErrNotFound
		}
		output = func(command string, _ []string, _ executil.Options) ([]byte, error) {
			if command == "atq" {
				return []byte("9 queued\n"), nil
			}
			return []byte("#!/bin/sh\n/bin/true\n"), nil
		}
		combinedOutput = func(string, []string, executil.Options) ([]byte, error) {
			t.Fatal("malformed job must not be removed without an owner")
			return nil, nil
		}
		if err := Clear("xxvcc-a1", 1001); err == nil || !strings.Contains(err.Error(), "no atrun owner header") {
			t.Fatalf("Clear error = %v, want missing-owner refusal", err)
		}
	})
}

func TestAtInventoryIgnoresOnlyAConfirmedDisappearance(t *testing.T) {
	tests := []struct {
		name        string
		secondQueue string
		wantErr     bool
	}{
		{name: "disappeared"},
		{name: "still queued", secondQueue: "7 queued\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isolateJobHelpers(t)
			queueCalls := 0
			output = func(command string, _ []string, _ executil.Options) ([]byte, error) {
				switch command {
				case "atq":
					queueCalls++
					if queueCalls == 1 {
						return []byte("7 queued\n"), nil
					}
					return []byte(test.secondQueue), nil
				case "at":
					return nil, errors.New("job changed while reading")
				default:
					return nil, fmt.Errorf("unexpected command %s", command)
				}
			}

			jobs, err := inventoryAtJobs(context.Background())
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "read at job 7") {
					t.Fatalf("inventoryAtJobs error = %v, want surviving-job refusal", err)
				}
				return
			}
			if err != nil || len(jobs) != 0 {
				t.Fatalf("inventoryAtJobs = (%v, %v), want empty inventory after confirmed disappearance", jobs, err)
			}
		})
	}
}

func TestFailedAtRemovalRequiresConfirmedAbsence(t *testing.T) {
	tests := []struct {
		name    string
		queue   string
		wantErr bool
	}{
		{name: "gone"},
		{name: "still queued", queue: "7 queued\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isolateJobHelpers(t)
			atReads := 0
			combinedOutput = func(command string, args []string, _ executil.Options) ([]byte, error) {
				if command != "atrm" || !reflect.DeepEqual(args, []string{"7"}) {
					t.Fatalf("unexpected removal command: %s %v", command, args)
				}
				return []byte("job already running\n"), errors.New("exit 1")
			}
			output = func(command string, _ []string, _ executil.Options) ([]byte, error) {
				switch command {
				case "at":
					atReads++
					if atReads == 1 || test.queue != "" {
						return []byte("# atrun uid=1001 gid=1001\n"), nil
					}
					return nil, errors.New("job disappeared")
				case "atq":
					return []byte(test.queue), nil
				default:
					t.Fatalf("unexpected inventory command: %s", command)
					return nil, nil
				}
			}

			err := removeAtJob(context.Background(), "7", 1001)
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "job already running") {
					t.Fatalf("removeAtJob error = %v, want surviving-job refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("removeAtJob error after confirmed disappearance: %v", err)
			}
		})
	}
}

func TestClearAtJobsFinalInventoryCatchesANewTargetJob(t *testing.T) {
	isolateJobHelpers(t)
	lookPath = func(command string) (string, error) {
		switch command {
		case "at", "atq", "atrm":
			return "/mock/" + command, nil
		default:
			return "", exec.ErrNotFound
		}
	}
	queueCalls := 0
	output = func(command string, _ []string, _ executil.Options) ([]byte, error) {
		switch command {
		case "atq":
			queueCalls++
			if queueCalls == 1 {
				return nil, nil
			}
			return []byte("9 queued\n"), nil
		case "at":
			return []byte("# atrun uid=1001 gid=1001\n"), nil
		default:
			return nil, fmt.Errorf("unexpected command %s", command)
		}
	}
	combinedOutput = func(string, []string, executil.Options) ([]byte, error) {
		t.Fatal("a job absent from the initial inventory must not reach removal")
		return nil, nil
	}

	err := clearAtJobs(1001)
	if err == nil || !strings.Contains(err.Error(), "still exists after removal") {
		t.Fatalf("clearAtJobs error = %v, want final-inventory refusal", err)
	}
}

func TestClearAtJobsDoesNotRemoveAReusedJobID(t *testing.T) {
	isolateJobHelpers(t)
	lookPath = func(command string) (string, error) {
		switch command {
		case "at", "atq", "atrm":
			return "/mock/" + command, nil
		default:
			return "", exec.ErrNotFound
		}
	}
	atReads := 0
	output = func(command string, _ []string, _ executil.Options) ([]byte, error) {
		switch command {
		case "atq":
			return []byte("7 queued\n"), nil
		case "at":
			atReads++
			uid := 1001
			if atReads > 1 {
				uid = 2002
			}
			return []byte(fmt.Sprintf("# atrun uid=%d gid=%d\n", uid, uid)), nil
		default:
			return nil, fmt.Errorf("unexpected command %s", command)
		}
	}
	combinedOutput = func(command string, _ []string, _ executil.Options) ([]byte, error) {
		if command == "atrm" {
			t.Fatal("reused at job ID reached atrm after its owner changed")
		}
		return nil, fmt.Errorf("unexpected command %s", command)
	}
	if err := clearAtJobs(1001); err != nil {
		t.Fatalf("clearAtJobs treated another UID's replacement job as the target: %v", err)
	}
}

func TestClearRefusesAStaleNamedCronSpoolWithoutCrontabTool(t *testing.T) {
	isolateJobHelpers(t)
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	path := filepath.Join(cronSpoolDirectories[0], "xxvcc-a1")
	if err := os.WriteFile(path, []byte("* * * * * /bin/true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Clear("xxvcc-a1", 1001); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("Clear error = %v, want stale cron spool refusal", err)
	}
}

func TestAtJobIDMustBeCanonicalAndBounded(t *testing.T) {
	tests := []struct {
		id   string
		want bool
	}{
		{id: "1", want: true},
		{id: "18446744073709551615", want: true},
		{id: ""},
		{id: "0"},
		{id: "01"},
		{id: "+1"},
		{id: "1a"},
		{id: "184467440737095516150"},
	}
	for _, test := range tests {
		if got := numericJobID(test.id); got != test.want {
			t.Errorf("numericJobID(%q) = %t, want %t", test.id, got, test.want)
		}
	}
}

func TestParseAtOwnerFailsClosedOnAmbiguousOrInvalidHeaders(t *testing.T) {
	tests := []struct {
		name string
		body string
		want uint32
		err  string
	}{
		{
			name: "valid",
			body: "#!/bin/sh\n# atrun uid=1001 gid=2002\n/bin/true\n",
			want: 1001,
		},
		{
			name: "valid high kernel IDs",
			body: "# atrun uid=4294967294 gid=4294967294\n",
			want: 4294967294,
		},
		{
			name: "missing",
			body: "#!/bin/sh\n/bin/true\n",
			err:  "no atrun owner header",
		},
		{
			name: "user body may repeat owner-shaped comment",
			body: "# atrun uid=1001 gid=1001\n# atrun uid=2002 gid=2002\n",
			want: 1001,
		},
		{
			name: "malformed first owner header",
			body: "# atrun owner is unknown\n# atrun uid=1001 gid=1001\n",
			err:  "invalid atrun owner header",
		},
		{
			name: "negative UID",
			body: "# atrun uid=-1 gid=1001\n",
			err:  "invalid atrun UID",
		},
		{
			name: "reserved GID",
			body: "# atrun uid=1001 gid=4294967295\n",
			err:  "invalid atrun GID",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseAtOwner([]byte(test.body))
			if test.err == "" {
				if err != nil || got != test.want {
					t.Fatalf("parseAtOwner() = (%d, %v), want (%d, nil)", got, err, test.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.err) {
				t.Fatalf("parseAtOwner() error = %v, want %q", err, test.err)
			}
		})
	}
}

func TestSpoolInspectionRefusesSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	if _, err := namedSpoolArtifacts([]string{link}, "xxvcc-a1"); err == nil {
		t.Fatal("namedSpoolArtifacts accepted a symlinked spool directory")
	}
	if _, err := ownedSpoolArtifacts([]string{link}, 1001); err == nil {
		t.Fatal("ownedSpoolArtifacts accepted a symlinked spool directory")
	}
}

func TestNamedSpoolInspectionDoesNotFollowEntrySymlink(t *testing.T) {
	directory := t.TempDir()
	entry := filepath.Join(directory, "xxvcc-a1")
	if err := os.Symlink(filepath.Join(directory, "missing-target"), entry); err != nil {
		t.Fatal(err)
	}
	artifacts, err := namedSpoolArtifacts([]string{directory}, "xxvcc-a1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(artifacts, []string{entry}) {
		t.Fatalf("namedSpoolArtifacts = %v, want broken symlink reported as %s", artifacts, entry)
	}
}

func TestOwnedSpoolInspectionDoesNotFollowEntrySymlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership distinction requires root")
	}
	root := t.TempDir()
	directory := filepath.Join(root, "spool")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("job\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(target, 1001, 1001); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "job")); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(directory, "owned-job")
	if err := os.WriteFile(owned, []byte("job\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(owned, 1001, 1001); err != nil {
		t.Fatal(err)
	}
	artifacts, err := ownedSpoolArtifacts([]string{directory}, 1001)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(artifacts, []string{owned}) {
		t.Fatalf("ownedSpoolArtifacts = %v, want only direct UID-owned entry %s", artifacts, owned)
	}
}

func TestWaitForDrainCoversACompleteDaemonPollingCycle(t *testing.T) {
	isolateJobHelpers(t)
	lookPath = func(command string) (string, error) {
		if command == "crontab" {
			return "/mock/crontab", nil
		}
		return "", exec.ErrNotFound
	}
	var slept time.Duration
	drainSleep = func(delay time.Duration) { slept = delay }
	if err := WaitForDrain(); err != nil {
		t.Fatal(err)
	}
	if slept != 65*time.Second {
		t.Fatalf("drain wait = %s, want 65s", slept)
	}
}

func TestWaitForDrainReturnsImmediatelyWithoutCronOrAtTools(t *testing.T) {
	isolateJobHelpers(t)
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	drainSleep = func(time.Duration) { t.Fatal("WaitForDrain slept without cron or at tooling") }
	if err := WaitForDrain(); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForDrainRecognizesDaemonAndBatchFootprints(t *testing.T) {
	for _, available := range []string{"cron", "crond", "batch"} {
		t.Run(available, func(t *testing.T) {
			isolateJobHelpers(t)
			lookPath = func(command string) (string, error) {
				if command == available {
					return "/mock/" + command, nil
				}
				return "", exec.ErrNotFound
			}
			var slept time.Duration
			drainSleep = func(delay time.Duration) { slept = delay }
			if err := WaitForDrain(); err != nil {
				t.Fatal(err)
			}
			if slept != 65*time.Second {
				t.Fatalf("drain wait = %s, want 65s for %s footprint", slept, available)
			}
		})
	}
}

func TestWaitForDrainRecognizesRunningDaemonWithoutInstalledTools(t *testing.T) {
	for _, daemon := range []string{"cron", "crond", "atd"} {
		t.Run(daemon, func(t *testing.T) {
			isolateJobHelpers(t)
			lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
			pidDir := filepath.Join(drainProcRoot, "123")
			if err := os.Mkdir(pidDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte(daemon+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var slept time.Duration
			drainSleep = func(delay time.Duration) { slept = delay }
			if err := WaitForDrain(); err != nil {
				t.Fatal(err)
			}
			if slept != 65*time.Second {
				t.Fatalf("drain wait = %s, want 65s for running %s", slept, daemon)
			}
		})
	}
}

func TestWaitForDrainWaitsWhenProcessInventoryIsUnreliable(t *testing.T) {
	isolateJobHelpers(t)
	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	drainProcRoot = filepath.Join(t.TempDir(), "missing")
	var slept time.Duration
	drainSleep = func(delay time.Duration) { slept = delay }
	if err := WaitForDrain(); err != nil {
		t.Fatal(err)
	}
	if slept != 65*time.Second {
		t.Fatalf("drain wait = %s, want conservative 65s after process inventory failure", slept)
	}
}

func TestClearTreatsBatchOnlyAsAnUnsafePartialAtInstallation(t *testing.T) {
	isolateJobHelpers(t)
	lookPath = func(command string) (string, error) {
		if command == "batch" {
			return "/mock/batch", nil
		}
		return "", exec.ErrNotFound
	}
	if err := Clear("xxvcc-a1", 1001); err == nil || !strings.Contains(err.Error(), "partial at installation") {
		t.Fatalf("Clear with batch-only backend error = %v, want partial-installation refusal", err)
	}
}
