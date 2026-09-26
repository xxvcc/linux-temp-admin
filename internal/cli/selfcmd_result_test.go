//go:build integration

package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/xxvcc/linux-temp-admin/internal/audit"
	"github.com/xxvcc/linux-temp-admin/internal/config"
	"github.com/xxvcc/linux-temp-admin/internal/fsutil"
	"github.com/xxvcc/linux-temp-admin/internal/lifecycle"
	"github.com/xxvcc/linux-temp-admin/internal/selfmanage"
)

func TestUpgradeMenuRetiresProcessAfterVisibleReplacement(t *testing.T) {
	for _, tc := range []struct {
		name            string
		installed       string
		writeFailure    string
		wantStatus      int
		wantReplaced    bool
		wantWrites      int
		wantMainPrompts int
	}{
		{name: "successful replacement", installed: "2.0.0", wantReplaced: true, wantWrites: 1, wantMainPrompts: 1},
		{name: "replacement with durability failure", installed: "2.0.0", writeFailure: "after", wantStatus: 1, wantReplaced: true, wantWrites: 1, wantMainPrompts: 1},
		{name: "failure before replacement", installed: "2.0.0", writeFailure: "before", wantStatus: 1, wantWrites: 1, wantMainPrompts: 2},
		{name: "already current", installed: "2.0.1", wantMainPrompts: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := rootOwnedDir(t)
			upgradeChoice, exitChoice := 0, 0
			for i, item := range menuItems {
				if item.en == "Upgrade" {
					upgradeChoice = i + 1
				}
				if item.run == nil {
					exitChoice = i + 1
				}
			}
			if upgradeChoice == 0 || exitChoice == 0 {
				t.Fatal("real menu is missing upgrade or exit")
			}
			a, out, errb := newTestApp(t, fmt.Sprintf("%d\nYES\n%d\n", upgradeChoice, exitChoice))
			a.InstallPath = filepath.Join(dir, "linux-temp-admin")
			a.Lifecycle = lifecycle.New(filepath.Join(dir, "lifecycle.lock"))
			auditDir := filepath.Join(dir, "audit")
			auditPath := filepath.Join(auditDir, "audit.log")
			a.Audit = &audit.Logger{Dir: auditDir, File: auditPath, Now: a.Now, Actor: func() (string, int) { return "test", 0 }}
			pub, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			binary := func(version string) []byte {
				return []byte("#!/bin/sh\n# LTA_RELEASE_VERSION_V1{" + version + "}\n[ \"$1\" = version ] && echo " + version + "\n")
			}
			old, candidate := binary(tc.installed), binary("2.0.1")
			signature := ed25519.Sign(private, candidate)
			asset := config.BinaryAssetPrefix + runtime.GOARCH
			base := config.ReleaseMirrorBaseURL + "/v2.0.1"
			payloads := map[string][]byte{
				config.ReleaseMirrorManifestURL: []byte(fmt.Sprintf(`{"version":"2.0.1","tag":"v2.0.1","base_url":%q,"published_at":"2026-07-27T05:00:00Z"}`, base) + "\n"),
				base + "/SHA256SUMS":            releaseSetSums(asset, candidate, signature),
				base + "/" + asset:              candidate,
				base + "/" + asset + ".sig":     signature,
			}
			m := &selfmanage.Manager{
				InstallPath: a.InstallPath, RequireHostMachine: cliAllowAnyMachine,
				PublicKey: pub, MaxBytes: config.MaxUpgradeBytes,
				Client: &http.Client{Transport: cliRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					body, ok := payloads[req.URL.String()]
					if !ok {
						return nil, fmt.Errorf("unexpected fixture request: %s", req.URL)
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
				})},
			}
			a.Selfmanage = m
			if _, err := m.Install(old, false); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(a.InstallPath)
			if err != nil {
				t.Fatal(err)
			}
			writeCalls := 0
			m.WriteRootFile = func(path string, content []byte, mode os.FileMode) error {
				writeCalls++
				if tc.writeFailure == "before" {
					return syscall.EIO
				}
				if err := fsutil.WriteRootFile(path, content, mode); err != nil {
					return err
				}
				if tc.writeFailure == "after" {
					return &fsutil.DurabilityError{Operation: "rename", Err: syscall.EIO}
				}
				return nil
			}

			if status := a.menu(); status != tc.wantStatus {
				t.Fatalf("menu status=%d, want %d; %s", status, tc.wantStatus, errb)
			}
			if writeCalls != tc.wantWrites {
				t.Fatalf("upgrade writer called %d times, want %d; %s", writeCalls, tc.wantWrites, errb)
			}
			mainPrompt := fmt.Sprintf("select [1-%d] (Enter shows the menu): ", len(menuItems))
			if prompts := strings.Count(errb.String(), mainPrompt); prompts != tc.wantMainPrompts {
				t.Fatalf("menu prompted %d times, want %d after visible replacement=%t; %s", prompts, tc.wantMainPrompts, tc.wantReplaced, errb)
			}
			wantBytes := old
			if tc.wantReplaced {
				wantBytes = candidate
			}
			actual, readErr := os.ReadFile(a.InstallPath)
			if readErr != nil || !bytes.Equal(actual, wantBytes) {
				t.Fatalf("visible command bytes match=%t, err=%v", bytes.Equal(actual, wantBytes), readErr)
			}
			after, statErr := os.Stat(a.InstallPath)
			if statErr != nil || os.SameFile(before, after) == tc.wantReplaced {
				t.Fatalf("actual inode replacement does not match expected=%t: %v", tc.wantReplaced, statErr)
			}
			if tc.writeFailure != "" {
				wantDiagnostic := "upgrade failed"
				wantAudit := "upgrade failed before replacement: "
				if tc.writeFailure == "after" {
					wantDiagnostic = "upgrade's durability is unknown"
					wantAudit = "2.0.0 -> 2.0.1 visible but durability unknown: "
				}
				if !strings.Contains(errb.String(), wantDiagnostic) || !strings.Contains(errb.String(), syscall.EIO.Error()) || strings.Contains(out.String(), "upgraded to") {
					t.Fatalf("injected write failure diagnostic is wrong: stdout=%q stderr=%q", out, errb)
				}
				events, readErr := os.ReadFile(auditPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				matched := false
				for _, line := range bytes.Split(bytes.TrimSpace(events), []byte("\n")) {
					var event struct {
						Action string `json:"action"`
						Result string `json:"result"`
						Detail string `json:"detail"`
					}
					if err := json.Unmarshal(line, &event); err != nil {
						t.Fatal(err)
					}
					if event.Action == "upgrade" && event.Result == "fail" && strings.Contains(event.Detail, wantAudit) && strings.Contains(event.Detail, syscall.EIO.Error()) {
						matched = true
					}
				}
				if !matched {
					t.Fatalf("injected write failure missing from audit: %s", events)
				}
			}
		})
	}
}
